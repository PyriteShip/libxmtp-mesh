package org.xmtp.android.library.mesh.policy

/**
 * Android silently stops delivering results to an app that starts scanning more
 * than [maxStarts] times in [windowMs] (5 per 30 s), counted per app. [ScanSchedule]
 * keeps one scanner under that; the radio uses the process-wide [process] limiter,
 * so restarts (Bluetooth toggled, Mesh.stop then Mesh.start) count too.
 * Synchronized: an old radio thread may still be stopping as a new one starts.
 */
class ScanStartLimiter(
    private val maxStarts: Int = 5,
    private val windowMs: Long = 30_000,
) {
    private val starts = ArrayDeque<Long>()

    /** How long to wait before a scan may start at [nowMs]; 0 = now. */
    @Synchronized
    fun delayMs(nowMs: Long): Long {
        prune(nowMs)
        if (starts.size < maxStarts) return 0
        return starts.first() + windowMs - nowMs
    }

    @Synchronized
    fun record(nowMs: Long) {
        prune(nowMs)
        starts.addLast(nowMs)
    }

    private fun prune(nowMs: Long) {
        while (starts.isNotEmpty() && nowMs - starts.first() >= windowMs) starts.removeFirst()
    }

    companion object {
        /** Android counts scan starts per app, so the radio shares one limiter per process. */
        val process = ScanStartLimiter()
    }
}
