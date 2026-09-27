use futures::future::try_join_all;
use prost::Message;
use xmtp_id::associations::unverified::UnverifiedIdentityUpdate;
use xmtp_id::associations::{self, AssociationState, IdentityUpdate};
use xmtp_proto::types::ApiIdentifier;
use xmtp_proto::xmtp::identity::api::v1::{
    GetIdentityUpdatesRequest, GetIdentityUpdatesResponse, GetInboxIdsRequest, GetInboxIdsResponse,
    PublishIdentityUpdateRequest, PublishIdentityUpdateResponse,
    VerifySmartContractWalletSignaturesRequest, VerifySmartContractWalletSignaturesResponse,
    get_identity_updates_response::{IdentityUpdateLog, Response as UpdatesResponse},
    get_inbox_ids_response::Response as InboxIdResponse,
    verify_smart_contract_wallet_signatures_response::ValidationResponse,
};
use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

use super::{MeshNode, NodeEvent};
use crate::{EoaOnlyVerifier, MeshError};

pub(crate) async fn verify(proto: &IdentityUpdateProto) -> Result<IdentityUpdate, MeshError> {
    let unverified = UnverifiedIdentityUpdate::try_from(proto.clone())
        .map_err(|e| MeshError::IdentityRejected(e.to_string()))?;
    unverified
        .to_verified(EoaOnlyVerifier)
        .await
        .map_err(|e| MeshError::IdentityRejected(e.to_string()))
}

/// A node accepts at most this many stale-snapshot retries before reporting a
/// conflict (see `accept_identity_update`).
const MAX_ACCEPT_ATTEMPTS: u32 = 3;

impl MeshNode {
    /// Verified association state of an inbox, built from the stored log,
    /// together with the number of rows it was built from.
    async fn verified_state_and_len(
        &self,
        inbox_id: &str,
    ) -> Result<(Option<AssociationState>, i64), MeshError> {
        let rows = self.inner.store.lock().identity_rows(inbox_id, 0)?;
        let len = rows.len() as i64;
        if rows.is_empty() {
            return Ok((None, 0));
        }
        let protos = rows
            .iter()
            .map(|r| IdentityUpdateProto::decode(r.update_bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()?;
        let updates = try_join_all(protos.iter().map(verify)).await?;
        let state = associations::get_state(&updates)
            .map_err(|e| MeshError::IdentityRejected(e.to_string()))?;
        Ok((Some(state), len))
    }

    /// Verified association state of an inbox, built from the stored log.
    pub(crate) async fn verified_state(
        &self,
        inbox_id: &str,
    ) -> Result<Option<AssociationState>, MeshError> {
        self.verified_state_and_len(inbox_id)
            .await
            .map(|(state, _)| state)
    }

    /// Verify an update, check it applies to the current state, and append it
    /// at the next index (Rule B). Returns the sequence id it was stored at.
    ///
    /// `verified_state_and_len` reads its rows and verifies signatures without
    /// holding the store lock (verification is async). If another update for
    /// the same inbox is accepted concurrently in that window, the row count
    /// the state was built from (`base_count`) will disagree with the store's
    /// count once we take the lock to write; when that happens the snapshot is
    /// stale, so we drop the lock and recompute against fresh state, up to
    /// `MAX_ACCEPT_ATTEMPTS` times before giving up with `IdentityConflict`.
    pub(crate) async fn accept_identity_update(
        &self,
        proto: IdentityUpdateProto,
        expected_seq: Option<i64>,
        server_ts: Option<i64>,
        local: bool,
    ) -> Result<i64, MeshError> {
        let inbox_id = proto.inbox_id.clone();
        let update = verify(&proto).await?;

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let (existing_state, base_count) = self.verified_state_and_len(&inbox_id).await?;
            let state = match existing_state {
                None => associations::get_state([update.clone()]),
                Some(existing_state) => associations::apply_update(existing_state, update.clone()),
            }
            .map_err(|e| MeshError::IdentityRejected(e.to_string()))?;

            let mut store = self.inner.store.lock();
            let current_count = store.identity_len(&inbox_id)?;
            if current_count != base_count {
                // A concurrent update for this inbox landed while we verified
                // against a now-stale snapshot; retry against fresh state.
                drop(store);
                if attempt >= MAX_ACCEPT_ATTEMPTS {
                    return Err(MeshError::IdentityConflict {
                        inbox_id,
                        expected: current_count + 1,
                        got: base_count + 1,
                    });
                }
                continue;
            }

            let next_seq = current_count + 1;
            if let Some(caller_expected_seq) = expected_seq
                && caller_expected_seq != next_seq
            {
                return Err(MeshError::IdentityConflict {
                    inbox_id,
                    expected: next_seq,
                    got: caller_expected_seq,
                });
            }
            store.append_identity(
                &inbox_id,
                next_seq,
                server_ts.unwrap_or_else(Self::now_ns),
                &proto.encode_to_vec(),
            )?;
            for identifier in state.identifiers() {
                let api: ApiIdentifier = (&identifier).into();
                store.set_identifier(&api.identifier, api.identifier_kind as i32, &inbox_id)?;
            }
            if local && store.local_inbox()?.is_none() {
                store.set_local_inbox(&inbox_id)?;
            }
            drop(store);
            let mut events = vec![NodeEvent::IdentityLogChanged(inbox_id.clone())];
            if local {
                events.push(NodeEvent::LocalIdentityChanged);
            }
            self.emit(events);
            return Ok(next_seq);
        }
    }

    pub(crate) async fn publish_identity_update(
        &self,
        req: PublishIdentityUpdateRequest,
    ) -> Result<PublishIdentityUpdateResponse, MeshError> {
        let proto = req
            .identity_update
            .ok_or_else(|| MeshError::InvalidRequest("missing identity_update".into()))?;
        self.accept_identity_update(proto, None, None, true).await?;
        Ok(PublishIdentityUpdateResponse {})
    }

    pub(crate) fn get_identity_updates(
        &self,
        req: GetIdentityUpdatesRequest,
    ) -> Result<GetIdentityUpdatesResponse, MeshError> {
        let mut store = self.inner.store.lock();
        let mut responses = Vec::with_capacity(req.requests.len());
        for r in req.requests {
            let updates = store
                .identity_rows(&r.inbox_id, r.sequence_id as i64)?
                .into_iter()
                .map(|row| {
                    Ok(IdentityUpdateLog {
                        sequence_id: row.sequence_id as u64,
                        server_timestamp_ns: row.server_timestamp_ns as u64,
                        update: Some(IdentityUpdateProto::decode(row.update_bytes.as_slice())?),
                    })
                })
                .collect::<Result<Vec<_>, MeshError>>()?;
            responses.push(UpdatesResponse {
                inbox_id: r.inbox_id,
                updates,
            });
        }
        Ok(GetIdentityUpdatesResponse { responses })
    }

    pub(crate) fn get_inbox_ids(
        &self,
        req: GetInboxIdsRequest,
    ) -> Result<GetInboxIdsResponse, MeshError> {
        let mut store = self.inner.store.lock();
        let responses = req
            .requests
            .into_iter()
            .map(|r| {
                Ok(InboxIdResponse {
                    inbox_id: store.inbox_for_identifier(&r.identifier, r.identifier_kind)?,
                    identifier: r.identifier,
                    identifier_kind: r.identifier_kind,
                })
            })
            .collect::<Result<Vec<_>, MeshError>>()?;
        Ok(GetInboxIdsResponse { responses })
    }

    pub(crate) fn verify_scw_signatures(
        &self,
        req: VerifySmartContractWalletSignaturesRequest,
    ) -> VerifySmartContractWalletSignaturesResponse {
        VerifySmartContractWalletSignaturesResponse {
            responses: req
                .signatures
                .iter()
                .map(|_| ValidationResponse {
                    is_valid: false,
                    block_number: None,
                    error: Some("smart contract wallets are not supported on the mesh".into()),
                })
                .collect(),
        }
    }
}
