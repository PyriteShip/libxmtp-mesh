package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.AdvertMatch
import org.xmtp.android.library.mesh.policy.BackoffTracker
import org.xmtp.android.library.mesh.policy.DialPlanner
import org.xmtp.android.library.mesh.policy.DialPlanner.Decision
import org.xmtp.android.library.mesh.policy.DialPlanner.Intent

/** Who dials whom (DESIGN.md §B7.2, §B14.2). */
class DialPlannerTest {
    private val planner = DialPlanner()

    private fun inputs(
        match: AdvertMatch,
        waitingSinceMs: Long = 0,
        nowMs: Long = 0,
        lastLostMs: Long? = null,
        relayOn: Boolean = true,
        busy: Boolean = false,
        backoffAllows: Boolean = true,
        openConnections: Int = 0,
        relayLinks: Int = 0,
        evictableRelayKey: String? = null,
    ) = DialPlanner.Inputs(
        match,
        waitingSinceMs,
        lastLostMs,
        nowMs,
        relayOn,
        busy,
        backoffAllows,
        openConnections,
        relayLinks,
        evictableRelayKey,
    )

    /** Strangers get at most 2 of the 4 slots (DESIGN.md §B7.2). */
    @Test
    fun relayDialsStopAtTheRelayCap() {
        val m = AdvertMatch.Stranger(relayOffered = true, dialFirst = true)
        assertEquals(Decision.Dial(Intent.Relay), planner.decide(inputs(m, openConnections = 1, relayLinks = 1)))
        assertTrue(planner.decide(inputs(m, openConnections = 2, relayLinks = 2)) is Decision.Skip)
    }

    /** Four strangers cannot starve a contact: with every slot taken, a contact dial evicts a relay link. */
    @Test
    fun aContactOrPairingDialEvictsARelayLinkWhenFull() {
        val c = AdvertMatch.Contact("bob", dialFirst = true)
        assertEquals(
            Decision.Dial(Intent.Contact("bob"), evictKey = "c:R1"),
            planner.decide(inputs(c, openConnections = 4, relayLinks = 2, evictableRelayKey = "c:R1")),
        )
        assertEquals(
            Decision.Dial(Intent.Pairing, evictKey = "s:R2"),
            planner.decide(
                inputs(AdvertMatch.Pairing(true), openConnections = 4, relayLinks = 1, evictableRelayKey = "s:R2"),
            ),
        )
        assertTrue(planner.decide(inputs(c, openConnections = 4, relayLinks = 0)) is Decision.Skip)
    }

    /** A free slot never evicts. */
    @Test
    fun aContactDialWithAFreeSlotEvictsNothing() {
        val c = AdvertMatch.Contact("bob", dialFirst = true)
        assertEquals(
            Decision.Dial(Intent.Contact("bob")),
            planner.decide(inputs(c, openConnections = 3, relayLinks = 2, evictableRelayKey = "c:R1")),
        )
    }

    @Test
    fun aRelayDialNeverEvicts() {
        val m = AdvertMatch.Stranger(true, true)
        assertTrue(
            planner.decide(inputs(m, openConnections = 4, relayLinks = 1, evictableRelayKey = "c:R1")) is Decision.Skip,
        )
    }

    @Test
    fun inboundRelayLinksBeyondTheCapAreClosedNewestFirst() {
        assertEquals(listOf("s:C"), planner.relayLinksToClose(listOf("s:A", "c:B", "s:C")))
        assertEquals(emptyList<String>(), planner.relayLinksToClose(listOf("s:A", "c:B")))
    }

    @Test
    fun theLowerTokenDialsAContactAtOnce() {
        assertEquals(
            Decision.Dial(Intent.Contact("bob")),
            planner.decide(inputs(AdvertMatch.Contact("bob", dialFirst = true))),
        )
    }

    @Test
    fun theHigherTokenDialsAContactOnlyAfterTheFallback() {
        val m = AdvertMatch.Contact("bob", dialFirst = false)
        assertTrue(planner.decide(inputs(m, waitingSinceMs = 0, nowMs = 44_999)) is Decision.Skip)
        assertEquals(
            Decision.Dial(Intent.Contact("bob")),
            planner.decide(inputs(m, waitingSinceMs = 0, nowMs = 45_000)),
        )
    }

    @Test
    fun pairingFollowsTheSameRule() {
        assertEquals(Decision.Dial(Intent.Pairing), planner.decide(inputs(AdvertMatch.Pairing(dialFirst = true))))
        assertTrue(planner.decide(inputs(AdvertMatch.Pairing(dialFirst = false), nowMs = 1_000)) is Decision.Skip)
    }

    @Test
    fun aStrangerIsDialedForRelayOnlyWhenBothOfferItAndOurTokenIsLower() {
        assertEquals(
            Decision.Dial(Intent.Relay),
            planner.decide(inputs(AdvertMatch.Stranger(relayOffered = true, dialFirst = true))),
        )
        assertTrue(planner.decide(inputs(AdvertMatch.Stranger(true, true), relayOn = false)) is Decision.Skip)
        assertTrue(
            planner.decide(inputs(AdvertMatch.Stranger(relayOffered = false, dialFirst = true))) is Decision.Skip,
        )
        assertTrue(
            planner.decide(inputs(AdvertMatch.Stranger(true, dialFirst = false), nowMs = 600_000)) is Decision.Skip,
        )
    }

    @Test
    fun ignoredAdvertsAreNeverDialed() {
        assertTrue(planner.decide(inputs(AdvertMatch.Ignore, nowMs = 600_000)) is Decision.Skip)
    }

    /** Both phones in the same window: a contact with a link or a dial in flight is never dialed again. */
    @Test
    fun aContactWithALinkOrDialInFlightIsNotDialedAgain() {
        val m = AdvertMatch.Contact("bob", dialFirst = true)
        assertTrue(planner.decide(inputs(m, busy = true)) is Decision.Skip)
        assertTrue(planner.isBusy("c:bob", dialedKeys = listOf("c:bob"), verifiedInboxes = emptyList()))
        assertTrue(planner.isBusy("c:bob", dialedKeys = emptyList(), verifiedInboxes = listOf("bob")))
    }

    /** After a reset the other phone may see us as a stranger and hold a relay link to us: our contact dial still goes. */
    @Test
    fun aContactIsDialedEvenWhileARelayLinkToTheSameDeviceIsOpen() {
        assertFalse(planner.isBusy("c:bob", dialedKeys = listOf("d:AA:BB"), verifiedInboxes = emptyList()))
    }

    @Test
    fun backoffCooldownAndFullSlotsHoldADial() {
        val m = AdvertMatch.Contact("bob", dialFirst = true)
        assertTrue(planner.decide(inputs(m, backoffAllows = false)) is Decision.Skip)
        assertTrue(planner.decide(inputs(m, lastLostMs = 0, nowMs = 1_999)) is Decision.Skip)
        assertTrue(planner.decide(inputs(m, openConnections = 4)) is Decision.Skip)
    }

    @Test
    fun sightingKeysAreStablePerContactAndPerDeviceOtherwise() {
        assertEquals("c:bob", planner.sightingKey(AdvertMatch.Contact("bob", true), "AA:BB"))
        assertEquals("d:AA:BB", planner.sightingKey(AdvertMatch.Stranger(true, true), "AA:BB"))
        assertEquals("d:AA:BB", planner.sightingKey(AdvertMatch.Pairing(true), "AA:BB"))
        assertNull(planner.sightingKey(AdvertMatch.Ignore, "AA:BB"))
    }

    @Test
    fun aNewVisitStartsAfterTheAbsenceGap() {
        assertEquals(100L, planner.sightingStart(firstSeenMs = 100, lastSeenMs = 50_000, nowMs = 60_000))
        assertEquals(200_000L, planner.sightingStart(firstSeenMs = 100, lastSeenMs = 100_000, nowMs = 200_000))
        assertFalse(planner.acceptInbound(4))
    }

    /** An address we closed over the relay cap is refused for a while, even with slots free. */
    @Test
    fun aCoolingDownAddressIsRefusedInbound() {
        assertTrue(planner.acceptInbound(1, coolingDown = false))
        assertFalse(planner.acceptInbound(1, coolingDown = true))
    }

    /**
     * A contact's back-off is per inbox and device: a device replaying a contact's token (it
     * never completes IK) backs off only itself, never our dials to the real contact.
     */
    @Test
    fun aContactBackOffIsPerInboxAndDevice() {
        val b = BackoffTracker()
        val replayer = DialPlanner.contactBackoffKey("c:bob", "AA:AA")
        val real = DialPlanner.contactBackoffKey("c:bob", "BB:BB")
        b.onFailure(replayer, 0)
        assertFalse(b.canAttempt(replayer, 1))
        assertTrue(b.canAttempt(real, 1))
        // Any verified link to bob resets bob's back-off on every device.
        b.onFailure(real, 0)
        b.onSuccessWithPrefix(DialPlanner.contactBackoffPrefix("bob"))
        assertTrue(b.canAttempt(replayer, 1))
        assertTrue(b.canAttempt(real, 1))
        // ...and nobody else's.
        val carol = DialPlanner.contactBackoffKey("c:carol", "AA:AA")
        b.onFailure(carol, 0)
        b.onSuccessWithPrefix(DialPlanner.contactBackoffPrefix("bob"))
        assertFalse(b.canAttempt(carol, 1))
    }

    /** A contact dial is keyed per inbox and device; anything else keeps its sighting key. */
    @Test
    fun theDialKeyOfAContactIncludesItsDevice() {
        assertEquals("c:bob@AA", DialPlanner.dialKey("c:bob", "AA"))
        assertEquals("d:AA", DialPlanner.dialKey("d:AA", "AA"))
    }

    /**
     * A device replaying bob's token from one address (it never completes IK and its GATT dials
     * fail) never blocks a sighting of bob at another address: not by the GATT back-off, not by
     * a dial in flight. A verified link to bob still makes every bob sighting busy.
     */
    @Test
    fun aReplayerAtOneAddressNeverBlocksTheContactAtAnother() {
        val gatt = BackoffTracker()
        val replayer = DialPlanner.dialKey("c:bob", "AA")
        val real = DialPlanner.dialKey("c:bob", "BB")
        repeat(5) { gatt.onFailure(replayer, 0) }
        assertFalse(gatt.canAttempt(replayer, 1))
        assertTrue(gatt.canAttempt(real, 1))
        assertFalse(planner.isBusy(real, dialedKeys = listOf(replayer), verifiedInboxes = emptyList()))
        assertTrue(planner.isBusy(replayer, dialedKeys = listOf(replayer), verifiedInboxes = emptyList()))
        assertTrue(planner.isBusy(real, dialedKeys = emptyList(), verifiedInboxes = listOf("bob")))
        assertFalse(planner.isBusy(real, dialedKeys = emptyList(), verifiedInboxes = listOf("bobby")))
        // A verified link to bob clears bob on every address.
        gatt.onSuccessWithPrefix(DialPlanner.contactBackoffPrefix("bob"))
        assertTrue(gatt.canAttempt(replayer, 1))
    }
}
