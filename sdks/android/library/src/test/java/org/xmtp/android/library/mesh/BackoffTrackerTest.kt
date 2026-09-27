package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.BackoffTracker
import kotlin.random.Random

class BackoffTrackerTest {
    /** nextDouble() == 0.0, so the jitter factor is exactly 0.8. */
    private object ZeroRandom : Random() {
        override fun nextBits(bitCount: Int): Int = 0
    }

    @Test
    fun delays_double_then_cool_down_after_max_attempts() {
        val b = BackoffTracker(random = ZeroRandom)
        assertEquals(800, b.onFailure("p", 0))
        assertEquals(1_600, b.onFailure("p", 0))
        assertEquals(3_200, b.onFailure("p", 0))
        assertEquals(6_400, b.onFailure("p", 0))
        assertEquals(120_000, b.onFailure("p", 0)) // 5th failure: cooldown
        assertFalse(b.canAttempt("p", 119_999))
        assertTrue(b.canAttempt("p", 120_000))
        assertEquals(800, b.onFailure("p", 120_000)) // counter restarted
    }

    @Test
    fun delay_is_capped() {
        val b = BackoffTracker(maxAttempts = 20, random = ZeroRandom)
        repeat(9) { b.onFailure("p", 0) }
        assertEquals(24_000, b.onFailure("p", 0)) // 30 s cap × 0.8
    }

    @Test
    fun success_clears_and_penalize_blocks() {
        val b = BackoffTracker(random = ZeroRandom)
        b.onFailure("p", 0)
        assertFalse(b.canAttempt("p", 100))
        b.onSuccess("p")
        assertTrue(b.canAttempt("p", 100))
        b.penalize("p", 100)
        assertFalse(b.canAttempt("p", 100 + 119_999))
        assertTrue(b.canAttempt("q", 0))
    }
}
