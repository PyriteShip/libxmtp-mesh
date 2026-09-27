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
    // One clock reading for the tokens and both plans (no window-edge flake).
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
        hub.planned_link_at_for_test("a", "b", now),
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
        hub.planned_link_at_for_test("a", "b", now),
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

/// Cards are exchanged once per pair: a removal survives later links and
/// simulated re-links (§B14.4).
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_contact_stays_removed_across_re_links() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    assert!(
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| !c.removed)
    );
    assert!(a.node.remove_contact(&inbox(&b)).unwrap());
    hub.unlink("a", "b");
    hub.link("a", "b");
    assert!(
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| c.removed),
        "still removed"
    );
    assert!(a.node.contacts().unwrap().is_empty());
    // a no longer recognises b: if a dials, it dials as a stranger.
    if let Some((dialer, intent)) = hub.planned_link_for_test("a", "b") {
        if dialer == "a" {
            assert_eq!(intent, DialIntent::Relay);
        }
    }
}
