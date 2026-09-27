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
    /// start) is signed by `start_sync`, before any session exists; the
    /// signer then stays set across `stop_sync`.
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
            rows[1].seq_signer.is_some(),
            "the signer outlives stop_sync"
        );
        assert_eq!(node.mesh_stats().seq_rows_signed, 2);
    }
}
