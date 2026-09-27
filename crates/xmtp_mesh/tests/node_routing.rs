use bytes::Bytes;
use http::{request, uri::PathAndQuery};
use xmtp_mesh::MeshNode;
use xmtp_proto::api::{Client, IsConnectedCheck, ToBoxedClient};

#[tokio::test]
async fn unknown_path_is_unimplemented() {
    let node = MeshNode::in_memory().unwrap();
    let err = node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.bogus.v1.Nope/Nothing"),
            Bytes::new(),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Nothing"), "{err}");
}

#[tokio::test]
async fn node_is_always_connected_and_boxes_into_a_v3_bundle() {
    let node = MeshNode::in_memory().unwrap();
    assert!(node.is_connected().await);
    // Must type-check: this is exactly how the bindings will plug the node in.
    let _bundle = xmtp_api_d14n::ClientBundle::v3(node.clone().arced());
}
