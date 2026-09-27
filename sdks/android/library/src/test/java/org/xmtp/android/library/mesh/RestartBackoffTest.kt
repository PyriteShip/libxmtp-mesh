package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test
import org.xmtp.android.library.mesh.policy.RestartBackoff

class RestartBackoffTest {
    @Test
    fun doubles_from_one_second_and_caps_at_thirty() {
        val backoff = RestartBackoff()
        val delays = List(8) { backoff.nextDelayMs() }
        assertEquals(listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L, 30_000L, 30_000L, 30_000L), delays)
    }

    @Test
    fun reset_starts_over() {
        val backoff = RestartBackoff()
        repeat(4) { backoff.nextDelayMs() }
        backoff.reset()
        assertEquals(1_000L, backoff.nextDelayMs())
    }
}
