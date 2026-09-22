/// True when `path` is the gRPC method whose request type is `T`.
pub(crate) fn is<T: prost::Name>(path: &str) -> bool {
    xmtp_proto::path_and_query::<T>() == path
}
