use async_trait::async_trait;
use xmtp_configuration::MAX_INSTALLATIONS_PER_INBOX;
use xmtp_mls::client::ClientError;
use xmtp_mls::context::XmtpSharedContext;
use xmtp_mls::db::prelude::QueryIdentityUpdates;
use xmtp_mls::mls_store::MlsStoreError;

use crate::MeshError;
use crate::node::ResyncOutcome;

/// The local libxmtp client, as the node's sync sees it: who belongs to a
/// group (sync sessions scope all group traffic to members, see the crate
/// docs), and what the client must do when the node replaces an identity
/// log (restore convergence §C4.3).
#[async_trait]
pub trait GroupMembership: Send + Sync {
    /// Inbox ids of the group's current members, or `Ok(None)` when the local
    /// client does not know the group (yet), e.g. before it processed the
    /// welcome.
    async fn member_inboxes(&self, group_id: &[u8]) -> Result<Option<Vec<String>>, MeshError>;

    /// The node replaced `inbox_id`'s identity log: the client drops its
    /// copy and every state cached from it, reloads, and says whether its
    /// own installation must re-base (§C4.4).
    async fn identity_log_replaced(&self, _inbox_id: &str) -> Result<ResyncOutcome, MeshError> {
        Ok(ResyncOutcome::Reloaded)
    }

    /// The installation ids (leaf signature keys) of the group's current
    /// leaves per the local client, or `Ok(None)` when it does not know the
    /// group. The §C4.7 sequencer handover picks from them.
    async fn leaf_installations(
        &self,
        _group_id: &[u8],
    ) -> Result<Option<Vec<Vec<u8>>>, MeshError> {
        Ok(None)
    }
}

/// The production [`GroupMembership`]: reads the member list of a group from
/// an xmtp_mls client's local database (`Client::group` + `MlsGroup::members`).
pub struct ClientGroupMembership<C>(pub xmtp_mls::Client<C>);

#[async_trait]
impl<C> GroupMembership for ClientGroupMembership<C>
where
    C: XmtpSharedContext + Send + Sync + 'static,
{
    async fn member_inboxes(&self, group_id: &[u8]) -> Result<Option<Vec<String>>, MeshError> {
        let group = match self.0.group(&group_id.to_vec()) {
            Ok(group) => group,
            Err(ClientError::MlsStore(MlsStoreError::NotFound(_))) => return Ok(None),
            Err(e) => return Err(MeshError::Membership(e.to_string())),
        };
        let members = group
            .members()
            .await
            .map_err(|e| MeshError::Membership(e.to_string()))?;
        Ok(Some(members.into_iter().map(|m| m.inbox_id).collect()))
    }

    async fn identity_log_replaced(&self, inbox_id: &str) -> Result<ResyncOutcome, MeshError> {
        // Only resync an inbox this client has
        // actually loaded. Skipping the fetch and purge for one it never
        // touched avoids pulling a log it never asked for into its
        // database; the loaded/not-loaded check itself is a fast local
        // read, so this is cheap even when it turns out the inbox is ours.
        // Fail open (treat "can't tell" as "resync anyway") rather than
        // silently skip a resync this client needed.
        let has_rows = self
            .0
            .db()
            .count_inbox_updates(&[inbox_id])
            .map(|counts| counts.get(inbox_id).copied().unwrap_or(0) > 0)
            .unwrap_or(true);
        if !has_rows {
            return Ok(ResyncOutcome::Reloaded);
        }
        let state = self
            .0
            .identity_updates()
            .resync_identity_log(inbox_id)
            .await
            .map_err(|e| MeshError::LocalClient(e.to_string()))?;
        if inbox_id != self.0.inbox_id() {
            return Ok(ResyncOutcome::Reloaded);
        }
        let installations = state.installation_ids();
        let own = self.0.installation_public_key().to_vec();
        Ok(if installations.contains(&own) {
            ResyncOutcome::Reloaded
        } else if installations.len() >= MAX_INSTALLATIONS_PER_INBOX {
            ResyncOutcome::TooManyInstallations
        } else {
            ResyncOutcome::RebaseNeeded
        })
    }

    async fn leaf_installations(&self, group_id: &[u8]) -> Result<Option<Vec<Vec<u8>>>, MeshError> {
        let group = match self.0.group(&group_id.to_vec()) {
            Ok(group) => group,
            Err(ClientError::MlsStore(MlsStoreError::NotFound(_))) => return Ok(None),
            Err(e) => return Err(MeshError::Membership(e.to_string())),
        };
        group
            .leaf_installation_ids()
            .map(Some)
            .map_err(|e| MeshError::Membership(e.to_string()))
    }
}
