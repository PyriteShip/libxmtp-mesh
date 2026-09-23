use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use futures::StreamExt;
use prost::Message;
use tokio::sync::broadcast::{Receiver, error::RecvError};
use xmtp_proto::mls_v1::{SubscribeGroupMessagesRequest, SubscribeWelcomeMessagesRequest};

use super::welcomes::welcome_to_proto;
use super::{MeshNode, MeshStream, NodeEvent};
use crate::MeshError;

const BACKLOG_PAGE: i64 = 1_000;

struct GroupSub {
    node: MeshNode,
    rx: Receiver<NodeEvent>,
    cursors: HashMap<Vec<u8>, i64>,
    ready: VecDeque<Bytes>,
}

impl GroupSub {
    /// Re-read everything after each cursor from the store (backlog / lag recovery).
    ///
    /// A single page may not cover the whole backlog, so each cursor is paged
    /// until a page comes back short (fewer than `BACKLOG_PAGE` rows); the
    /// store lock is held for the whole call (never across an `.await`), so
    /// this can't race a concurrent writer leaving a later page stranded.
    fn refill(&mut self) -> Result<(), MeshError> {
        let mut store = self.node.inner.store.lock();
        for (gid, cursor) in self.cursors.iter_mut() {
            loop {
                let page = store.query_group(gid, *cursor, BACKLOG_PAGE, false)?;
                let page_len = page.len() as i64;
                for row in page {
                    *cursor = row.id;
                    self.ready
                        .push_back(Bytes::from(row.to_proto().encode_to_vec()));
                }
                if page_len < BACKLOG_PAGE {
                    break;
                }
            }
        }
        Ok(())
    }
}

struct WelcomeSub {
    node: MeshNode,
    rx: Receiver<NodeEvent>,
    cursors: HashMap<Vec<u8>, i64>,
    ready: VecDeque<Bytes>,
}

impl WelcomeSub {
    /// See `GroupSub::refill`: pages until a page comes back short, so a
    /// backlog bigger than one page is never stranded.
    fn refill(&mut self) -> Result<(), MeshError> {
        let mut store = self.node.inner.store.lock();
        for (installation, cursor) in self.cursors.iter_mut() {
            loop {
                let page = store.query_welcomes(installation, *cursor, BACKLOG_PAGE)?;
                let page_len = page.len() as i64;
                for row in page {
                    *cursor = row.id;
                    self.ready
                        .push_back(Bytes::from(welcome_to_proto(&row)?.encode_to_vec()));
                }
                if page_len < BACKLOG_PAGE {
                    break;
                }
            }
        }
        Ok(())
    }
}

impl MeshNode {
    pub(crate) fn subscribe_group_messages(
        &self,
        req: SubscribeGroupMessagesRequest,
    ) -> Result<MeshStream, MeshError> {
        // Subscribe before reading the backlog so nothing falls in between.
        let rx = self.subscribe_events();
        let mut newly_known = Vec::new();
        // Events accumulated for filters already processed must be emitted
        // even if a later filter in this loop errors out (same "emit on
        // every exit path" rule as send_group_messages / send_welcome_messages),
        // so the locked loop runs in an inner closure and `newly_known` is
        // emitted unconditionally before the closure's `Result` is propagated.
        let result = (|| -> Result<(), MeshError> {
            let mut store = self.inner.store.lock();
            for f in &req.filters {
                if store.ensure_group(&f.group_id)? {
                    newly_known.push(NodeEvent::GroupKnown(f.group_id.clone()));
                }
            }
            Ok(())
        })();
        self.emit(newly_known);
        result?;
        let mut sub = GroupSub {
            node: self.clone(),
            rx,
            cursors: req
                .filters
                .into_iter()
                .map(|f| (f.group_id, f.id_cursor as i64))
                .collect(),
            ready: VecDeque::new(),
        };
        sub.refill()?;
        Ok(futures::stream::unfold(sub, |mut sub| async move {
            loop {
                if let Some(item) = sub.ready.pop_front() {
                    return Some((Ok(item), sub));
                }
                match sub.rx.recv().await {
                    Ok(NodeEvent::GroupSequenced(row)) => {
                        if let Some(cursor) = sub.cursors.get_mut(&row.group_id) {
                            if row.id == *cursor + 1 {
                                *cursor = row.id;
                                sub.ready
                                    .push_back(Bytes::from(row.to_proto().encode_to_vec()));
                            } else if row.id > *cursor + 1 {
                                // out-of-order event: read the gap from the store
                                if sub.refill().is_err() {
                                    return None;
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        if sub.refill().is_err() {
                            return None;
                        }
                    }
                    Err(RecvError::Closed) => return None,
                }
            }
        })
        .boxed())
    }

    pub(crate) fn subscribe_welcome_messages(
        &self,
        req: SubscribeWelcomeMessagesRequest,
    ) -> Result<MeshStream, MeshError> {
        let rx = self.subscribe_events();
        let mut sub = WelcomeSub {
            node: self.clone(),
            rx,
            cursors: req
                .filters
                .into_iter()
                .map(|f| (f.installation_key, f.id_cursor as i64))
                .collect(),
            ready: VecDeque::new(),
        };
        sub.refill()?;
        Ok(futures::stream::unfold(sub, |mut sub| async move {
            loop {
                if let Some(item) = sub.ready.pop_front() {
                    return Some((Ok(item), sub));
                }
                match sub.rx.recv().await {
                    Ok(NodeEvent::WelcomeStored(_)) | Err(RecvError::Lagged(_)) => {
                        if sub.refill().is_err() {
                            return None;
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Closed) => return None,
                }
            }
        })
        .boxed())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;
    use prost::Message;
    use xmtp_proto::mls_v1::{GroupMessage, group_message, subscribe_group_messages_request};

    use super::*;
    use crate::store::NewGroupMessage;

    /// A backlog bigger than one `BACKLOG_PAGE` must be fully yielded (in
    /// order, no gaps) before the stream falls through to live events —
    /// `refill` has to keep paging per cursor rather than stopping after the
    /// first page.
    #[tokio::test(flavor = "multi_thread")]
    async fn group_backlog_larger_than_one_page_is_fully_yielded_before_live() {
        let node = MeshNode::in_memory().unwrap();
        let group_id = b"backlog-group".to_vec();
        let total = BACKLOG_PAGE + 5;

        {
            let mut store = node.inner.store.lock();
            store.ensure_group(&group_id).unwrap();
            for i in 0..total {
                let msg = NewGroupMessage {
                    group_id: group_id.clone(),
                    data: format!("msg-{i}").into_bytes(),
                    sender_hmac: vec![],
                    should_push: false,
                    is_commit: false,
                };
                store.append_sequenced(&msg, i).unwrap();
            }
        }
        assert_eq!(node.max_group_id_for_test(&group_id).unwrap(), total);

        let req = SubscribeGroupMessagesRequest {
            filters: vec![subscribe_group_messages_request::Filter {
                group_id: group_id.clone(),
                id_cursor: 0,
            }],
        };
        let mut stream = node.subscribe_group_messages(req).unwrap();

        let mut ids = vec![];
        while (ids.len() as i64) < total {
            let item = tokio::time::timeout(Duration::from_secs(10), stream.next())
                .await
                .expect("stream stalled")
                .unwrap()
                .unwrap();
            let Some(group_message::Version::V1(v1)) = GroupMessage::decode(item).unwrap().version
            else {
                panic!("expected V1");
            };
            ids.push(v1.id as i64);
        }
        assert_eq!(
            ids,
            (1..=total).collect::<Vec<_>>(),
            "every backlog row exactly once, in order"
        );
        // nothing further arrives: the whole backlog (both pages) was drained, not just page 1
        assert!(
            tokio::time::timeout(Duration::from_millis(300), stream.next())
                .await
                .is_err()
        );
    }
}
