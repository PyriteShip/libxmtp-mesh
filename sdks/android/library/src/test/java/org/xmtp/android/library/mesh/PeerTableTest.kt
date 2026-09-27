package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.PeerTable
import org.xmtp.android.library.mesh.policy.PeerTable.LinkRef
import org.xmtp.android.library.mesh.policy.PeerTable.Role

class PeerTableTest {
    private val me = "1111111111111111"
    private val peer = "2222222222222222"

    @Test
    fun first_link_connects_peer_under_a_connection_scoped_id() {
        val t = PeerTable(me)
        val d = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL))
        assertTrue(d.keep)
        assertNull(d.closeKey)
        assertNull(d.lostPeerId)
        val id = d.connectedPeerId!!
        assertTrue(id, id.startsWith("$peer#"))
        assertEquals(id, t.peerIdOf(peer))
        assertEquals("c:AA", t.keyForPeerId(id))
        assertEquals(peer, t.shortIdOf(id))
        assertEquals("c:AA", t.activeKey(peer))
    }

    @Test
    fun second_link_for_same_peer_is_not_a_new_peer() {
        // Same phone, new random BLE address, second link while the first is open.
        val t = PeerTable(me)
        val id = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId
        val d = t.onLinkReady(peer, LinkRef("s:BB", Role.PERIPHERAL))
        assertFalse(d.keep)
        assertEquals("s:BB", d.closeKey) // me < peer: keep the link where I am central
        assertNull(d.lostPeerId)
        assertNull(d.connectedPeerId)
        assertEquals("c:AA", t.activeKey(peer))
        assertEquals(id, t.peerIdOf(peer))
        assertEquals(setOf(peer), t.peers())
    }

    @Test
    fun preferred_second_link_replaces_connection_under_a_new_peer_id() {
        val t = PeerTable(me)
        val first = t.onLinkReady(peer, LinkRef("s:BB", Role.PERIPHERAL)).connectedPeerId!!
        val d = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)) // me < peer: central wins
        assertTrue(d.keep)
        assertEquals("s:BB", d.closeKey)
        assertEquals(first, d.lostPeerId)
        val second = d.connectedPeerId!!
        assertNotEquals(first, second)
        assertNull(t.keyForPeerId(first))
        assertEquals("c:AA", t.keyForPeerId(second))
        // Closing the replaced link afterwards reports nothing more.
        assertNull(t.onLinkClosed(peer, "s:BB"))
        assertEquals(second, t.peerIdOf(peer))
    }

    @Test
    fun peer_lost_only_when_active_link_closes() {
        val t = PeerTable(me)
        val id = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId
        t.onLinkReady(peer, LinkRef("s:BB", Role.PERIPHERAL))
        assertNull(t.onLinkClosed(peer, "s:BB"))
        assertEquals(id, t.onLinkClosed(peer, "c:AA"))
        assertNull(t.activeKey(peer))
        assertNull(t.peerIdOf(peer))
        assertEquals(0, t.size)
    }

    @Test
    fun reconnect_gets_a_fresh_peer_id() {
        val t = PeerTable(me)
        val first = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId!!
        assertEquals(first, t.onLinkClosed(peer, "c:AA"))
        // Same phone, even the same link key: a new connection is a new Rust PeerId.
        val second = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId!!
        assertNotEquals(first, second)
        assertNull(t.keyForPeerId(first)) // a late send/disconnect for `first` reaches nothing
        assertEquals("c:AA", t.keyForPeerId(second))
    }

    @Test
    fun peer_ids_are_unique_across_tables() {
        // A restarted radio gets a new PeerTable; ids must still never repeat in the process.
        val a = PeerTable(me).onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId
        val b = PeerTable(me).onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId
        assertNotEquals(a, b)
    }

    @Test
    fun duplicate_links_resolve_identically_on_both_sides() {
        // Link X: phone A (lower id) is central. Link Y: phone B is central.
        val a = "0a0a0a0a0a0a0a0a"
        val b = "0b0b0b0b0b0b0b0b"
        val tableA = PeerTable(a)
        val tableB = PeerTable(b)
        // Opposite arrival orders on the two phones.
        val firstA = tableA.onLinkReady(b, LinkRef("Y", Role.PERIPHERAL)).connectedPeerId
        val dA = tableA.onLinkReady(b, LinkRef("X", Role.CENTRAL))
        val firstB = tableB.onLinkReady(a, LinkRef("X", Role.PERIPHERAL)).connectedPeerId
        val dB = tableB.onLinkReady(a, LinkRef("Y", Role.CENTRAL))
        assertEquals("X", tableA.activeKey(b))
        assertEquals("X", tableB.activeKey(a))
        assertEquals("Y", dA.closeKey)
        assertEquals("Y", dB.closeKey)
        // A's first link lost the tie: exactly one swap into Rust (lost old, connected new).
        assertEquals(firstA, dA.lostPeerId)
        assertNotEquals(firstA, dA.connectedPeerId)
        // B's first link was already the winner: Rust hears nothing more.
        assertNull(dB.lostPeerId)
        assertNull(dB.connectedPeerId)
        assertEquals(firstB, tableB.peerIdOf(a))
        // Never two Rust PeerIds for one phone at once.
        assertEquals(setOf(b), tableA.peers())
        assertEquals(setOf(a), tableB.peers())
    }

    @Test
    fun link_to_self_is_rejected() {
        val d = PeerTable(me).onLinkReady(me, LinkRef("c:ZZ", Role.CENTRAL))
        assertFalse(d.keep)
        assertEquals("c:ZZ", d.closeKey)
        assertNull(d.connectedPeerId)
    }

    // ---- duplicate link vs. a stale existing link (D23) ---------------------

    @Test
    fun duplicate_while_the_old_link_is_stale_the_new_link_wins_even_against_the_tie_break() {
        // me < peer normally prefers CENTRAL; the existing link already holds that role, so
        // an ordinary duplicate (existingIsStale = false) would keep it and close the new one
        // (see second_link_for_same_peer_is_not_a_new_peer above). Staleness overrides that.
        val t = PeerTable(me)
        val first = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId!!
        val d = t.onLinkReady(peer, LinkRef("s:BB", Role.PERIPHERAL), existingIsStale = true)
        assertTrue(d.keep)
        assertEquals("c:AA", d.closeKey)
        assertEquals(first, d.lostPeerId)
        val second = d.connectedPeerId!!
        assertNotEquals(first, second)
        assertEquals("s:BB", t.activeKey(peer))
        assertEquals(second, t.peerIdOf(peer))
        assertNull(t.keyForPeerId(first))
    }

    @Test
    fun duplicate_while_the_old_link_is_fresh_the_existing_tie_break_holds() {
        val t = PeerTable(me)
        val first = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL)).connectedPeerId!!
        val d = t.onLinkReady(peer, LinkRef("s:BB", Role.PERIPHERAL), existingIsStale = false)
        assertFalse(d.keep)
        assertEquals("s:BB", d.closeKey)
        assertNull(d.lostPeerId)
        assertNull(d.connectedPeerId)
        assertEquals("c:AA", t.activeKey(peer))
        assertEquals(first, t.peerIdOf(peer))
    }

    @Test
    fun both_sides_converge_when_the_existing_link_reads_stale_on_both() {
        // X is the existing (now stale, e.g. half-open) link; Y is the new, just-authenticated
        // one, and Y keeps the SAME role assignment as X on each side (peripheral for A,
        // central for B, exactly like X) — so without staleness, Y's role never differs from
        // the already-active link's role, and the ordinary tie-break would keep X and close Y
        // on both sides regardless of which of the two happens to hold the globally preferred
        // role for that phone. Staleness alone is what lets Y win here, and it does so
        // consistently on both phones.
        val a = "0a0a0a0a0a0a0a0a"
        val b = "0b0b0b0b0b0b0b0b"
        val tableA = PeerTable(a)
        val tableB = PeerTable(b)
        tableA.onLinkReady(b, LinkRef("X", Role.PERIPHERAL))
        tableB.onLinkReady(a, LinkRef("X", Role.CENTRAL))
        val dA = tableA.onLinkReady(b, LinkRef("Y", Role.PERIPHERAL), existingIsStale = true)
        val dB = tableB.onLinkReady(a, LinkRef("Y", Role.CENTRAL), existingIsStale = true)
        assertEquals("Y", tableA.activeKey(b))
        assertEquals("Y", tableB.activeKey(a))
        assertEquals("X", dA.closeKey)
        assertEquals("X", dB.closeKey)
        assertTrue(dA.keep)
        assertTrue(dB.keep)
    }

    @Test
    fun a_restarted_peers_first_link_needs_no_staleness_check_to_win() {
        // The realistic zombie scenario: the far side's process restarted, so ITS table has no
        // existing entry at all (existingIsStale is irrelevant there); it just gets a fresh
        // first link. Only the side that still remembers the dead link needs the stale rule.
        val t = PeerTable(me)
        val d = t.onLinkReady(peer, LinkRef("c:AA", Role.CENTRAL), existingIsStale = false)
        assertTrue(d.keep)
        assertNull(d.closeKey)
        assertEquals("c:AA", t.activeKey(peer))
    }

    // ---- isStale, the pure staleness threshold (D23) --------

    @Test
    fun a_gap_just_under_the_window_is_not_stale() {
        val keepaliveIntervalMs = 8_000L
        val window = 2 * keepaliveIntervalMs + PeerTable.DUPLICATE_STALE_MARGIN_MS
        assertFalse(
            PeerTable.isStale(lastInboundMs = 0L, nowMs = window - 1, keepaliveIntervalMs = keepaliveIntervalMs),
        )
    }

    @Test
    fun a_gap_at_the_window_is_stale() {
        val keepaliveIntervalMs = 8_000L
        val window = 2 * keepaliveIntervalMs + PeerTable.DUPLICATE_STALE_MARGIN_MS
        assertTrue(PeerTable.isStale(lastInboundMs = 0L, nowMs = window, keepaliveIntervalMs = keepaliveIntervalMs))
    }

    @Test
    fun no_last_inbound_at_all_counts_as_stale() {
        assertTrue(PeerTable.isStale(lastInboundMs = null, nowMs = 1_000L, keepaliveIntervalMs = 8_000L))
    }

    @Test
    fun a_healthy_links_worst_case_ping_gap_still_reads_as_fresh() {
        // ReliableLink's liveness check is a fixed-period timer, not reset by traffic, so a
        // keepalive Probe that becomes due just after one check can be delayed to almost the
        // next one — the worst-case gap between two inbound packets on a healthy, idle link is
        // just under 2x keepaliveIntervalMs (16 s at the default 8 s interval), not 1x. The old,
        // 5 s window read this gap as stale on every idle link; the current window must not.
        val keepaliveIntervalMs = 8_000L
        val worstCaseHealthyGapMs = 2 * keepaliveIntervalMs - 1
        assertFalse(
            PeerTable.isStale(
                lastInboundMs = 0L,
                nowMs = worstCaseHealthyGapMs,
                keepaliveIntervalMs = keepaliveIntervalMs,
            ),
        )
    }

    @Test
    fun the_dial_race_two_sides_see_different_gaps_for_the_same_healthy_link_but_still_agree_it_is_fresh() {
        // The scenario: a duplicate link is authenticated on both phones near-
        // simultaneously while the existing link is healthy but idle. A and B each judge that
        // existing link's staleness from their own inbound history, which can genuinely differ
        // by several seconds in a real dial race — here A last heard from it at t=0 and B at
        // t=4_000, and both check staleness at t=15_000 (an 15 s gap for A, 11 s for B). With
        // the old 5 s window (shorter than the 8 s keepalive), A's gap would have read stale
        // while B's would not: exactly the disagreement that made both phones close the link
        // the other one kept. With the fixed window (> 2x keepaliveIntervalMs + margin), neither
        // side calls it stale, so the ordinary, symmetric role tie-break decides for both (see
        // duplicate_links_resolve_identically_on_both_sides above), and they still converge.
        val a = "0a0a0a0a0a0a0a0a"
        val b = "0b0b0b0b0b0b0b0b"
        val tableA = PeerTable(a)
        val tableB = PeerTable(b)
        val keepaliveIntervalMs = 8_000L
        tableA.onLinkReady(b, LinkRef("X", Role.PERIPHERAL)) // a < b: A's preferred role is CENTRAL
        tableB.onLinkReady(a, LinkRef("X", Role.CENTRAL)) // b > a: B's preferred role is PERIPHERAL
        val aExistingIsStale =
            PeerTable.isStale(
                lastInboundMs = 0L,
                nowMs = 15_000L,
                keepaliveIntervalMs = keepaliveIntervalMs,
            )
        val bExistingIsStale =
            PeerTable.isStale(
                lastInboundMs = 4_000L,
                nowMs = 15_000L,
                keepaliveIntervalMs = keepaliveIntervalMs,
            )
        assertFalse("A must not read a 15 s-idle healthy link as stale", aExistingIsStale)
        assertFalse("B must not read an 11 s-idle healthy link as stale", bExistingIsStale)
        // Y takes each side's globally preferred role, so the ordinary tie-break swaps to it on
        // both phones — the same shape as duplicate_links_resolve_identically_on_both_sides.
        val dA = tableA.onLinkReady(b, LinkRef("Y", Role.CENTRAL), existingIsStale = aExistingIsStale)
        val dB = tableB.onLinkReady(a, LinkRef("Y", Role.PERIPHERAL), existingIsStale = bExistingIsStale)
        assertEquals("Y", tableA.activeKey(b))
        assertEquals("Y", tableB.activeKey(a))
        assertEquals("X", dA.closeKey)
        assertEquals("X", dB.closeKey)
    }
}
