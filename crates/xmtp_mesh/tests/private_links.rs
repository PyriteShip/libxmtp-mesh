#![recursion_limit = "256"]
//! Private discovery and Noise links (DESIGN.md §B14), end to end over
//! `LoopbackHub`.
mod common;

use common::{TestPeer, eventually, peer};
use xmtp_mesh::{DialIntent, LoopbackHub};

fn inbox(p: &TestPeer) -> String {
    p.client.inbox_id().to_string()
}

async fn verified_pair(a: &TestPeer, b: &TestPeer) {
    eventually("both verified", || async {
        a.node
            .verified_peers()
            .iter()
            .any(|p| p.installation == b.installation())
            && b.node
                .verified_peers()
                .iter()
                .any(|p| p.installation == a.installation())
    })
    .await;
}

/// The hub dials like the radio (§B14.2): the lower token dials; as a
/// contact once the pair has exchanged cards, which `link` does unless the
/// pair are strangers.
#[tokio::test(flavor = "multi_thread")]
async fn the_lower_token_dials_and_linked_pairs_are_contacts_by_default() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let now = a.node.unix_now();
    let (ta, tb) = (
        a.node.own_advert_token(now).unwrap(),
        b.node.own_advert_token(now).unwrap(),
    );
    let (dialer, other_inbox) = if ta <= tb {
        ("a", inbox(&b))
    } else {
        ("b", inbox(&a))
    };
    assert_eq!(
        hub.planned_link_for_test("a", "b"),
        Some((dialer.to_string(), DialIntent::Relay)),
        "strangers before any card"
    );
    hub.link("a", "b");
    assert_eq!(
        a.node.contact(&inbox(&b)).unwrap().map(|c| c.inbox_id),
        Some(inbox(&b))
    );
    assert_eq!(
        b.node.contact(&inbox(&a)).unwrap().map(|c| c.inbox_id),
        Some(inbox(&a))
    );
    assert_eq!(
        hub.planned_link_for_test("a", "b"),
        Some((
            dialer.to_string(),
            DialIntent::Contact {
                inbox_id: other_inbox
            }
        ))
    );
    verified_pair(&a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn strangers_never_learn_each_others_cards() {
    let hub = LoopbackHub::new();
    let c = peer(&hub, "c").await;
    let d = peer(&hub, "d").await;
    hub.set_strangers("c", "d");
    hub.link("c", "d");
    assert!(c.node.contacts().unwrap().is_empty());
    assert!(d.node.contacts().unwrap().is_empty());
    assert!(matches!(
        hub.planned_link_for_test("c", "d"),
        Some((_, DialIntent::Relay))
    ));
}
