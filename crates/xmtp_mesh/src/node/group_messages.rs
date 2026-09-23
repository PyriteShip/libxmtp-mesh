use xmtp_configuration::MAX_PAGE_SIZE;
use xmtp_proto::mls_v1::{
    BatchPublishCommitLogRequest, BatchQueryCommitLogRequest, BatchQueryCommitLogResponse,
    GetNewestGroupMessageRequest, GetNewestGroupMessageResponse, GroupMessage, PagingInfo,
    QueryCommitLogResponse, QueryGroupMessagesRequest, QueryGroupMessagesResponse,
    SendGroupMessagesRequest, SortDirection, get_newest_group_message_response, group_message,
    group_message_input,
};

use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::mls_parse::parse_group_message;
use crate::store::{NewGroupMessage, StoredGroupMessage, sha256};
use crate::sync::frames::{MAX_FRAME_LEN, single_message_frame_len};

fn check_frame_len(group_id: &[u8], v1: &group_message_input::V1) -> Result<(), MeshError> {
    let len = single_message_frame_len(group_id, v1);
    if len > MAX_FRAME_LEN {
        return Err(MeshError::InvalidRequest(format!(
            "group message needs a {len}-byte frame, over the {MAX_FRAME_LEN}-byte limit"
        )));
    }
    Ok(())
}

impl StoredGroupMessage {
    pub fn to_proto(&self) -> GroupMessage {
        GroupMessage {
            version: Some(group_message::Version::V1(group_message::V1 {
                id: self.id as u64,
                created_ns: self.created_ns as u64,
                group_id: self.group_id.clone(),
                data: self.data.clone(),
                sender_hmac: self.sender_hmac.clone(),
                should_push: self.should_push,
                is_commit: self.is_commit,
            })),
        }
    }
}

impl MeshNode {
    /// Rule A: sequence locally when this node is (or, at epoch 0, becomes)
    /// the group's sequencer; otherwise hold the message in pending.
    ///
    /// A message whose `Pending`/`Sequenced` frame would exceed
    /// [`MAX_FRAME_LEN`] is rejected, so libxmtp gets the error instead of a
    /// message that could never sync wedging the group.
    ///
    /// Events accumulated for items already processed in this batch must be
    /// emitted even if a later item in the batch errors out (store mutations
    /// for those earlier items are not rolled back), so the whole locked loop
    /// runs in an inner closure and `events` is emitted unconditionally
    /// before the closure's `Result` is propagated.
    pub(crate) fn send_group_messages(
        &self,
        req: SendGroupMessagesRequest,
    ) -> Result<(), MeshError> {
        let mut events = Vec::new();
        let result = (|| -> Result<(), MeshError> {
            let mut store = self.inner.store.lock();
            let local = store
                .local_installation()?
                .ok_or(MeshError::NotRegistered)?;
            for input in req.messages {
                let Some(group_message_input::Version::V1(v1)) = input.version else {
                    return Err(MeshError::InvalidRequest(
                        "group message input without V1".into(),
                    ));
                };
                // Cheap lower bound first (no group id), before parsing.
                check_frame_len(&[], &v1)?;
                let parsed = parse_group_message(&v1.data)?;
                check_frame_len(&parsed.group_id, &v1)?;
                let gid = parsed.group_id.clone();
                let msg = NewGroupMessage {
                    group_id: gid.clone(),
                    data: v1.data,
                    sender_hmac: v1.sender_hmac,
                    should_push: v1.should_push,
                    is_commit: parsed.is_commit,
                };
                if store.ensure_group(&gid)? {
                    events.push(NodeEvent::GroupKnown(gid.clone()));
                }
                let sequencer = match store.sequencer(&gid)? {
                    Some(s) => Some(s),
                    None if parsed.epoch == 0 => Some(store.pin_sequencer(&gid, &local)?),
                    None => None,
                };
                if sequencer.as_deref() == Some(local.as_slice()) {
                    let (row, inserted) = store.append_sequenced(&msg, Self::now_ns())?;
                    if inserted {
                        events.push(NodeEvent::GroupSequenced(row));
                    }
                } else if !store.is_sequenced(&gid, &sha256(&msg.data))? {
                    store.add_pending(&msg, Self::now_ns())?;
                    events.push(NodeEvent::PendingAdded(gid));
                }
            }
            Ok(())
        })();
        self.emit(events);
        result
    }

    pub(crate) fn query_group_messages(
        &self,
        req: QueryGroupMessagesRequest,
    ) -> Result<QueryGroupMessagesResponse, MeshError> {
        let paging = req.paging_info.unwrap_or_default();
        let limit = if paging.limit == 0 {
            MAX_PAGE_SIZE
        } else {
            paging.limit
        };
        let descending = paging.direction == SortDirection::Descending as i32;
        let mut events = Vec::new();
        let result = (|| -> Result<Vec<StoredGroupMessage>, MeshError> {
            let mut store = self.inner.store.lock();
            if store.ensure_group(&req.group_id)? {
                events.push(NodeEvent::GroupKnown(req.group_id.clone()));
            }
            store.query_group(
                &req.group_id,
                paging.id_cursor as i64,
                limit as i64,
                descending,
            )
        })();
        self.emit(events);
        let rows = result?;
        let next_cursor = if rows.len() as u32 == limit {
            rows.last().map(|r| r.id as u64).unwrap_or(0)
        } else {
            0
        };
        Ok(QueryGroupMessagesResponse {
            messages: rows.iter().map(StoredGroupMessage::to_proto).collect(),
            paging_info: Some(PagingInfo {
                direction: paging.direction,
                limit,
                id_cursor: next_cursor,
            }),
        })
    }

    pub(crate) fn get_newest_group_message(
        &self,
        req: GetNewestGroupMessageRequest,
    ) -> Result<GetNewestGroupMessageResponse, MeshError> {
        let mut store = self.inner.store.lock();
        let responses = req
            .group_ids
            .iter()
            .map(|gid| {
                let newest = store.query_group(gid, 0, 1, true)?.into_iter().next();
                Ok(get_newest_group_message_response::Response {
                    group_message: newest.map(|m| m.to_proto()),
                })
            })
            .collect::<Result<Vec<_>, MeshError>>()?;
        Ok(GetNewestGroupMessageResponse { responses })
    }

    /// Remote fork detection is not available without a shared log.
    pub(crate) fn publish_commit_log(&self, _req: BatchPublishCommitLogRequest) {}

    pub(crate) fn query_commit_log(
        &self,
        req: BatchQueryCommitLogRequest,
    ) -> BatchQueryCommitLogResponse {
        BatchQueryCommitLogResponse {
            responses: req
                .requests
                .into_iter()
                .map(|r| QueryCommitLogResponse {
                    group_id: r.group_id,
                    commit_log_entries: vec![],
                    paging_info: None,
                })
                .collect(),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn group_sequencer_for_test(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, MeshError> {
        self.inner.store.lock().sequencer(group_id)
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn first_sequenced_data_for_test(&self, group_id: &[u8]) -> Result<Vec<u8>, MeshError> {
        let mut rows = self.inner.store.lock().query_group(group_id, 0, 1, false)?;
        if rows.is_empty() {
            return Err(MeshError::NotFound("no sequenced message".into()));
        }
        Ok(rows.remove(0).data)
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn pending_count_for_test(&self, group_id: &[u8]) -> Result<usize, MeshError> {
        Ok(self.inner.store.lock().pending_for(group_id)?.len())
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn pending_inputs_for_test(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<xmtp_proto::mls_v1::GroupMessageInput>, MeshError> {
        self.pending_inputs(group_id)
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn max_group_id_for_test(&self, group_id: &[u8]) -> Result<i64, MeshError> {
        self.inner.store.lock().max_group_id(group_id)
    }
}
