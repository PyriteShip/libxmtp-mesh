use async_trait::async_trait;
use xmtp_mls::client::ClientError;
use xmtp_mls::context::XmtpSharedContext;
use xmtp_mls::mls_store::MlsStoreError;

use crate::MeshError;

/// Who belongs to a group, as the local libxmtp client sees it. Sync sessions
/// scope all group traffic to members (see the crate docs).
#[async_trait]
pub trait GroupMembership: Send + Sync {
    /// Inbox ids of the group's current members, or `Ok(None)` when the local
    /// client does not know the group (yet), e.g. before it processed the
    /// welcome.
    async fn member_inboxes(&self, group_id: &[u8]) -> Result<Option<Vec<String>>, MeshError>;
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
}
