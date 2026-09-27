//! Signed sequencing records on the node (DESIGN.md §B13): the counters,
//! and storing a received row only once its proof checks out.
use super::MeshNode;
use crate::sync::seq::MeshStats;

impl MeshNode {
    /// Signed-sequencing counters since this node was opened (§B13).
    pub fn mesh_stats(&self) -> MeshStats {
        self.inner.seq.snapshot()
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn sequenced_rows_for_test(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<crate::store::StoredGroupMessage>, crate::MeshError> {
        self.inner
            .store
            .lock()
            .query_group(group_id, 0, i64::MAX, false)
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn equivocations_for_test(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<crate::sync::seq::Equivocation>, crate::MeshError> {
        self.inner.store.lock().equivocations(group_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::node::test_logs::{Members, NoTransport};
    use crate::store::NewGroupMessage;
    use crate::sync::HelloSigner;
    use crate::sync::seq::{self, KeySigner};

    fn msg(data: &[u8]) -> NewGroupMessage {
        NewGroupMessage {
            group_id: b"g".to_vec(),
            data: data.to_vec(),
            sender_hmac: vec![],
            should_push: false,
            is_commit: false,
        }
    }

    /// §B13: a row sequenced while sync is stopped (here: before the first
    /// start) is signed by `start_sync`, before any session exists.
    /// `stop_sync` clears the store's signer (a Client-backed signer would
    /// otherwise hold the node alive forever, an Arc cycle): a row
    /// sequenced after that stays unsigned until the *next* `start_sync`'s
    /// backfill signs it, again before any session exists.
    #[tokio::test]
    async fn start_sync_signs_rows_sequenced_while_sync_was_stopped() {
        let signer = Arc::new(KeySigner::new());
        let node = MeshNode::in_memory().unwrap();
        {
            let mut store = node.inner.store.lock();
            store
                .set_local_installation(&signer.installation_key())
                .unwrap();
            store.append_sequenced(&msg(b"before"), 1).unwrap();
        }
        assert_eq!(
            node.sequenced_rows_for_test(b"g").unwrap()[0].seq_signer,
            None
        );

        node.start_sync(
            signer.clone(),
            Arc::new(NoTransport),
            Arc::new(Members(Some(vec![]))),
        )
        .unwrap();
        let rows = node.sequenced_rows_for_test(b"g").unwrap();
        assert_eq!(
            rows[0].seq_signer.as_deref(),
            Some(signer.installation_key().as_slice())
        );
        assert!(seq::verify_proof(b"g", 1, 1, b"before", &rows[0].proof()));
        assert_eq!(node.mesh_stats().seq_rows_signed, 1);

        node.stop_sync();
        node.inner
            .store
            .lock()
            .append_sequenced(&msg(b"after stop"), 2)
            .unwrap();
        let rows = node.sequenced_rows_for_test(b"g").unwrap();
        assert!(
            rows[1].seq_signer.is_none(),
            "cleared by stop_sync: nothing unsigned is ever served, since \
             serving only happens while sync runs"
        );
        assert_eq!(
            node.mesh_stats().seq_rows_signed,
            1,
            "not signed until the next start_sync backfill"
        );

        node.start_sync(
            signer.clone(),
            Arc::new(NoTransport),
            Arc::new(Members(Some(vec![]))),
        )
        .unwrap();
        let rows = node.sequenced_rows_for_test(b"g").unwrap();
        assert_eq!(
            rows[1].seq_signer.as_deref(),
            Some(signer.installation_key().as_slice()),
            "signed by the next start_sync's backfill"
        );
        assert!(seq::verify_proof(
            b"g",
            2,
            2,
            b"after stop",
            &rows[1].proof()
        ));
        assert_eq!(node.mesh_stats().seq_rows_signed, 2);
    }

    /// The review's Arc-cycle finding: a signer that itself holds a strong
    /// reference back to the node (as `ClientHelloSigner` does in
    /// production, through the client's own API bundle) must not be kept by
    /// the store past `stop_sync`, or the node could never be dropped after
    /// logout. This reproduces the cycle with an in-crate stand-in for
    /// `ClientHelloSigner` rather than a real libxmtp client (out of this
    /// crate's reach), and checks it is actually broken.
    #[test]
    fn stop_sync_drops_a_signer_that_holds_the_node_alive() {
        struct NodeHoldingSigner(KeySigner, #[allow(dead_code)] MeshNode);
        impl HelloSigner for NodeHoldingSigner {
            fn installation_key(&self) -> Vec<u8> {
                self.0.installation_key()
            }
            fn sign(&self, text: &str) -> Result<Vec<u8>, crate::MeshError> {
                self.0.sign(text)
            }
        }

        let node = MeshNode::in_memory().unwrap();
        let weak = Arc::downgrade(&node.inner);
        let signer: Arc<dyn HelloSigner> =
            Arc::new(NodeHoldingSigner(KeySigner::new(), node.clone()));
        node.inner.store.lock().set_seq_signer(signer.clone());
        drop(signer);
        drop(node);
        assert!(
            weak.upgrade().is_some(),
            "the signer's own clone of the node keeps it alive (the cycle)"
        );

        MeshNode {
            inner: weak.upgrade().unwrap(),
        }
        .stop_sync();
        assert!(
            weak.upgrade().is_none(),
            "stop_sync must clear the store's signer, or the node (and its \
             database) can never be dropped"
        );
    }
}
