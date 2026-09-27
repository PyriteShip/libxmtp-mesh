package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test
import org.xmtp.android.library.mesh.policy.ScanStartLimiter

class ScanStartLimiterTest {
    @Test
    fun five_starts_in_thirty_seconds_are_allowed() {
        val limiter = ScanStartLimiter()
        for (t in listOf(0L, 1_000L, 2_000L, 3_000L, 4_000L)) {
            assertEquals(0L, limiter.delayMs(t))
            limiter.record(t)
        }
    }

    @Test
    fun sixth_start_waits_until_the_oldest_leaves_the_window() {
        val limiter = ScanStartLimiter()
        for (t in listOf(0L, 1_000L, 2_000L, 3_000L, 4_000L)) limiter.record(t)
        assertEquals(25_000L, limiter.delayMs(5_000))
        assertEquals(0L, limiter.delayMs(30_000))
        limiter.record(30_000)
        // Window now holds 1s..4s and 30s: next start waits for the 1s start to age out.
        assertEquals(1_000L, limiter.delayMs(30_000))
    }

    @Test
    fun spaced_starts_never_wait() {
        val limiter = ScanStartLimiter()
        var t = 0L
        repeat(20) {
            assertEquals(0L, limiter.delayMs(t))
            limiter.record(t)
            t += SPACING_MS
        }
    }

    private companion object {
        const val SPACING_MS = 6_000L
    }
}

class ScanStartLimiterProcessTest {
    @Test
    fun process_limiter_is_one_instance() {
        org.junit.Assert.assertSame(ScanStartLimiter.process, ScanStartLimiter.process)
    }
}
