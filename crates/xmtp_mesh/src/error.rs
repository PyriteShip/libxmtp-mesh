use tonic::Status;

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("unimplemented endpoint {0}")]
    Unimplemented(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid MLS message: {0}")]
    InvalidMls(String),
    #[error("invalid key package: {0}")]
    InvalidKeyPackage(String),
    #[error("identity update rejected: {0}")]
    IdentityRejected(String),
    /// An update could not be appended at the sequence id it was offered for:
    /// `expected` is the id the store needs next (its length + 1), `got` is the
    /// id the caller claimed (or, after repeated concurrent appends, the id its
    /// stale snapshot implied).
    #[error("identity log conflict for {inbox_id}: expected {expected}, got {got}")]
    IdentityConflict {
        inbox_id: String,
        expected: i64,
        got: i64,
    },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("node has no local installation yet")]
    NotRegistered,
    #[error("sync not started")]
    SyncNotStarted,
    #[error("start_sync must be called from within a tokio runtime")]
    NoRuntime,
    #[error("peer authentication failed: {0}")]
    AuthFailed(String),
    #[error("peer installation is not a member of the inbox it claims")]
    PeerNotMember,
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("database: {0}")]
    Db(#[from] diesel::result::Error),
    #[error("database connection: {0}")]
    Connection(#[from] diesel::ConnectionError),
    #[error("migration: {0}")]
    Migration(String),
    /// The local client could not report a group's members.
    #[error("group membership: {0}")]
    Membership(String),
    /// The local libxmtp client failed a call the node made for it.
    #[error("local client: {0}")]
    LocalClient(String),
}

impl MeshError {
    /// gRPC status the in-process node reports, mirroring what xmtp-node-go
    /// would return for the same condition.
    pub fn into_status(self) -> Status {
        let msg = self.to_string();
        match self {
            MeshError::Unimplemented(_) => Status::unimplemented(msg),
            MeshError::NotFound(_) => Status::not_found(msg),
            MeshError::InvalidRequest(_)
            | MeshError::InvalidMls(_)
            | MeshError::InvalidKeyPackage(_)
            | MeshError::IdentityRejected(_)
            | MeshError::Decode(_) => Status::invalid_argument(msg),
            MeshError::IdentityConflict { .. } => Status::aborted(msg),
            MeshError::NotRegistered | MeshError::SyncNotStarted | MeshError::NoRuntime => {
                Status::failed_precondition(msg)
            }
            MeshError::AuthFailed(_) | MeshError::PeerNotMember => Status::permission_denied(msg),
            _ => Status::internal(msg),
        }
    }

    /// Errors after which a sync session must drop the peer.
    pub fn is_fatal(&self) -> bool {
        matches!(self, MeshError::AuthFailed(_) | MeshError::PeerNotMember)
    }
}
