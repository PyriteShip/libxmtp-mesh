// Deeply nested worker future types (xmtp_mls::worker::device_sync) overflow
// rustc's default query depth when this integration-test binary computes their
// layout. Same fix as crates/xmtp_mls/src/lib.rs:1 and bindings/*/src/lib.rs:1.
#![recursion_limit = "256"]

mod common;

use bytes::Bytes;
use common::build_client;
use http::{request, uri::PathAndQuery};
use xmtp_mesh::MeshNode;
use xmtp_proto::api::Client;

#[tokio::test(flavor = "multi_thread")]
async fn client_registers_against_mesh_node() {
    let node = MeshNode::in_memory().unwrap();
    let client = build_client(&node).await;
    let installation = client.installation_public_key().to_vec();

    assert_eq!(
        node.local_installation().unwrap(),
        Some(installation.clone())
    );
    assert_eq!(
        node.local_inbox().unwrap(),
        Some(client.inbox_id().to_string())
    );
    assert!(node.has_key_package(&installation).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn node_resolves_its_own_address_and_rejects_unknown_key_packages() {
    use prost::Message;
    use xmtp_proto::mls_v1::FetchKeyPackagesRequest;
    use xmtp_proto::xmtp::identity::api::v1::{
        GetInboxIdsRequest, GetInboxIdsResponse, get_inbox_ids_request,
    };

    let node = MeshNode::in_memory().unwrap();
    let client = build_client(&node).await;
    // `Client::context::identity()` (crates/xmtp_mls/src/identity.rs) does not
    // expose the wallet's `Identifier` at this commit; the client's verified
    // association state does (crates/xmtp_id/src/associations/state.rs:182).
    let state = client.inbox_state(false).await.unwrap();
    let identifier = state.identifiers().into_iter().next().unwrap();
    let api_ident: xmtp_proto::types::ApiIdentifier = (&identifier).into();

    let body = GetInboxIdsRequest {
        requests: vec![get_inbox_ids_request::Request {
            identifier: api_ident.identifier.clone(),
            identifier_kind: api_ident.identifier_kind as i32,
        }],
    }
    .encode_to_vec();
    let resp = node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.identity.api.v1.IdentityApi/GetInboxIds"),
            Bytes::from(body),
        )
        .await
        .unwrap();
    let resp = GetInboxIdsResponse::decode(resp.into_body()).unwrap();
    assert_eq!(
        resp.responses[0].inbox_id,
        Some(client.inbox_id().to_string())
    );

    // A single node serves exactly one installation; strangers have no key package.
    let body = FetchKeyPackagesRequest {
        installation_keys: vec![vec![0u8; 32]],
    }
    .encode_to_vec();
    let err = node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.mls.api.v1.MlsApi/FetchKeyPackages"),
            Bytes::from(body),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn second_installations_key_package_is_rejected_and_not_stored() {
    use prost::Message;
    use xmtp_proto::mls_v1::{
        FetchKeyPackagesRequest, FetchKeyPackagesResponse, KeyPackageUpload,
        UploadKeyPackageRequest,
    };

    // `node` already has a registered local installation.
    let node = MeshNode::in_memory().unwrap();
    let _resident = build_client(&node).await;

    // A second, unrelated installation with a real (verifiable) key package.
    let other_node = MeshNode::in_memory().unwrap();
    let other_client = build_client(&other_node).await;
    let other_installation = other_client.installation_public_key().to_vec();

    let body = FetchKeyPackagesRequest {
        installation_keys: vec![other_installation.clone()],
    }
    .encode_to_vec();
    let resp = other_node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.mls.api.v1.MlsApi/FetchKeyPackages"),
            Bytes::from(body),
        )
        .await
        .unwrap();
    let resp = FetchKeyPackagesResponse::decode(resp.into_body()).unwrap();
    let key_package_tls_serialized = resp.key_packages[0].key_package_tls_serialized.clone();

    // D7: one installation per inbox. Uploading it to `node` must be rejected
    // and must not leave a stored key package behind for that installation.
    let body = UploadKeyPackageRequest {
        key_package: Some(KeyPackageUpload {
            key_package_tls_serialized,
        }),
        is_inbox_id_credential: false,
    }
    .encode_to_vec();
    let err = node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.mls.api.v1.MlsApi/UploadKeyPackage"),
            Bytes::from(body),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("exactly one local installation"),
        "{err}"
    );
    assert!(!node.has_key_package(&other_installation).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_identity_update_is_rejected() {
    let node = MeshNode::in_memory().unwrap();
    let err = node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.identity.api.v1.IdentityApi/PublishIdentityUpdate"),
            Bytes::from_static(&[0x0a, 0x02, 0x08, 0x01]),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("rejected") || err.to_string().contains("invalid"),
        "{err}"
    );
}
