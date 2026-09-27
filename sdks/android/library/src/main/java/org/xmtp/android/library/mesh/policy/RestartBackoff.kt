package org.xmtp.android.library.mesh.policy

/** Delay before retrying a failed radio start: [baseMs] doubling up to [maxMs]. */
class RestartBackoff(
    private val baseMs: Long = 1_000,
    private val maxMs: Long = 30_000,
) {
    private var failures = 0

    fun nextDelayMs(): Long {
        val delay = minOf(maxMs, baseMs shl failures.coerceAtMost(20))
        failures++
        return delay
    }

    fun reset() {
        failures = 0
    }
}
