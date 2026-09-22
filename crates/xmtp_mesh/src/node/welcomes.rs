use prost::Message;
use xmtp_configuration::MAX_PAGE_SIZE;
use xmtp_proto::mls_v1::{
    PagingInfo, QueryWelcomeMessagesRequest, QueryWelcomeMessagesResponse,
    SendWelcomeMessagesRequest, WelcomeMessage, WelcomeMessageInput, welcome_message,
    welcome_message_input,
};

use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::store::{StoredWelcome, sha256};

pub(crate) fn welcome_recipient(input: &WelcomeMessageInput) -> Result<Vec<u8>, MeshError> {
    match &input.version {
        Some(welcome_message_input::Version::V1(v)) => Ok(v.installation_key.clone()),
        Some(welcome_message_input::Version::WelcomePointer(p)) => Ok(p.installation_key.clone()),
        None => Err(MeshError::InvalidRequest("welcome input without version".into())),
    }
}

pub(crate) fn welcome_to_proto(w: &StoredWelcome) -> Result<WelcomeMessage, MeshError> {
    let input = WelcomeMessageInput::decode(w.input.as_slice())?;
    let version = match input.version {
        Some(welcome_message_input::Version::V1(v)) => welcome_message::Version::V1(welcome_message::V1 {
            id: w.id as u64,
            created_ns: w.created_ns as u64,
            installation_key: v.installation_key,
            data: v.data,
            hpke_public_key: v.hpke_public_key,
            wrapper_algorithm: v.wrapper_algorithm,
            welcome_metadata: v.welcome_metadata,
        }),
        Some(welcome_message_input::Version::WelcomePointer(p)) => {
            welcome_message::Version::WelcomePointer(welcome_message::WelcomePointer {
                id: w.id as u64,
                created_ns: w.created_ns as u64,
                installation_key: p.installation_key,
                welcome_pointer: p.welcome_pointer,
                hpke_public_key: p.hpke_public_key,
                wrapper_algorithm: p.wrapper_algorithm,
            })
        }
        None => return Err(MeshError::InvalidRequest("stored welcome without version".into())),
    };
    Ok(WelcomeMessage { version: Some(version) })
}

impl MeshNode {
    /// Events accumulated for items already processed in this batch must be
    /// emitted even if a later item in the batch errors out (store mutations
    /// for those earlier items are not rolled back), so the whole locked loop
    /// runs in an inner closure and `events` is emitted unconditionally
    /// before the closure's `Result` is propagated.
    pub(crate) fn send_welcome_messages(&self, req: SendWelcomeMessagesRequest) -> Result<(), MeshError> {
        let mut events = Vec::new();
        let result = (|| -> Result<(), MeshError> {
            let mut store = self.inner.store.lock();
            let local = store.local_installation()?.ok_or(MeshError::NotRegistered)?;
            for input in req.messages {
                let recipient = welcome_recipient(&input)?;
                let bytes = input.encode_to_vec();
                let hash = sha256(&bytes);
                if recipient == local {
                    if let Some(stored) = store.append_welcome(&recipient, &hash, &bytes, Self::now_ns())? {
                        events.push(NodeEvent::WelcomeStored(stored));
                    }
                } else {
                    store.add_outbound_welcome(&hash, &recipient, &bytes)?;
                    events.push(NodeEvent::WelcomeOutbound(recipient));
                }
            }
            Ok(())
        })();
        self.emit(events);
        result
    }

    pub(crate) fn query_welcome_messages(&self, req: QueryWelcomeMessagesRequest) -> Result<QueryWelcomeMessagesResponse, MeshError> {
        let paging = req.paging_info.unwrap_or_default();
        let limit = if paging.limit == 0 { MAX_PAGE_SIZE } else { paging.limit };
        let rows = self
            .inner
            .store
            .lock()
            .query_welcomes(&req.installation_key, paging.id_cursor as i64, limit as i64)?;
        let next_cursor = if rows.len() as u32 == limit {
            rows.last().map(|r| r.id as u64).unwrap_or(0)
        } else {
            0
        };
        Ok(QueryWelcomeMessagesResponse {
            messages: rows.iter().map(welcome_to_proto).collect::<Result<_, _>>()?,
            paging_info: Some(PagingInfo { direction: paging.direction, limit, id_cursor: next_cursor }),
        })
    }
}
