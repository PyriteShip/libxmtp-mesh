package org.xmtp.android.library.mesh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.ConnectPolicy

class ConnectPolicyTest {
    private val p = ConnectPolicy()
    private val low = "0000000000000001"
    private val high = "ffffffffffffff00"

    private fun ok(
        local: String = low,
        remote: String = high,
        firstSeen: Long = 0,
        lastLost: Long? = null,
        now: Long = 1_000,
        busy: Boolean = false,
        open: Int = 0,
        backoff: Boolean = true,
    ) = p.shouldConnect(local, remote, firstSeen, lastLost, now, busy, open, backoff)

    @Test
    fun lower_id_initiates_immediately() = assertTrue(ok())

    @Test
    fun higher_id_waits_for_fallback() {
        assertFalse(ok(local = high, remote = low, now = 44_999))
        assertTrue(ok(local = high, remote = low, now = 45_000))
    }

    @Test
    fun never_to_self_or_twice() {
        assertFalse(ok(remote = low))
        assertFalse(ok(busy = true))
    }

    @Test
    fun respects_connection_budget_and_backoff() {
        assertFalse(ok(open = 4))
        assertTrue(ok(open = 3))
        assertFalse(ok(backoff = false))
        assertTrue(p.acceptInbound(3))
        assertFalse(p.acceptInbound(4))
    }

    @Test
    fun waits_after_losing_peer() {
        assertFalse(ok(lastLost = 0, now = 1_999))
        assertTrue(ok(lastLost = 0, now = 2_000))
    }

    /**
     * After a drop the lower id gets its head start again, so both phones
     * do not dial at once (duplicate links) on every reconnect.
     */
    @Test
    fun fallback_is_measured_from_the_last_drop() {
        // Near each other since t=0; the link dropped at t=100 s.
        assertFalse(ok(local = high, remote = low, firstSeen = 0, lastLost = 100_000, now = 102_000))
        assertTrue(ok(local = low, remote = high, firstSeen = 0, lastLost = 100_000, now = 102_000))
        assertFalse(ok(local = high, remote = low, firstSeen = 0, lastLost = 100_000, now = 144_999))
        assertTrue(ok(local = high, remote = low, firstSeen = 0, lastLost = 100_000, now = 145_000))
    }

    @Test
    fun sighting_after_an_absence_restarts_the_fallback_clock() {
        assertTrue(p.sightingStart(firstSeenMs = null, lastSeenMs = null, nowMs = 5) == 5L)
        // Seen again within the absence gap: same visit.
        assertTrue(p.sightingStart(firstSeenMs = 0, lastSeenMs = 50_000, nowMs = 100_000) == 0L)
        // Away longer than the gap: a new visit, so the lower id leads again.
        assertTrue(p.sightingStart(firstSeenMs = 0, lastSeenMs = 50_000, nowMs = 110_001) == 110_001L)
    }
}
