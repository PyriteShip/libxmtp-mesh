package org.xmtp.android.library.mesh.policy

data class ScanWindow(
    val onMs: Long,
    val offMs: Long,
)

/** Duty-cycled scanning (DESIGN.md §B7): slow when alone, faster while someone is around. */
class ScanSchedule(
    val idle: ScanWindow = ScanWindow(10_000, 20_000),
    val nearby: ScanWindow = ScanWindow(10_000, 5_000),
    val nearbyForMs: Long = 60_000,
) {
    init {
        require(idle.onMs + idle.offMs >= MIN_CYCLE_MS && nearby.onMs + nearby.offMs >= MIN_CYCLE_MS) {
            "Android throttles apps that start scanning more than 5 times per 30 s"
        }
    }

    fun window(
        nowMs: Long,
        lastSightingMs: Long?,
        connectedPeers: Int,
    ): ScanWindow {
        val recentlySeen = lastSightingMs != null && nowMs - lastSightingMs < nearbyForMs
        return if (connectedPeers > 0 || recentlySeen) nearby else idle
    }

    companion object {
        const val MIN_CYCLE_MS = 6_000L
    }
}
