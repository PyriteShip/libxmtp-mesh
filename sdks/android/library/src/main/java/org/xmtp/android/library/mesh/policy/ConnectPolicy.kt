package org.xmtp.android.library.mesh.policy

/** Who dials whom, and when (DESIGN.md §B7: max 4 concurrent connections). */
class ConnectPolicy(
    val maxConnections: Int = 4,
    val fallbackAfterMs: Long = 45_000,
    val reconnectCooldownMs: Long = 2_000,
    /** Unseen for longer than this, a peer's next sighting starts a new visit. */
    val absenceGapMs: Long = 60_000,
) {
    /**
     * The lower short id dials. The higher one dials only as a fallback, [fallbackAfterMs]
     * after the later of the visit's first sighting and the last link drop, so the lower id
     * gets its head start on every reconnect and both phones rarely dial at once.
     */
    fun shouldConnect(
        localPeerId: String,
        remotePeerId: String,
        firstSeenMs: Long,
        lastLostMs: Long?,
        nowMs: Long,
        hasLinkOrPending: Boolean,
        openConnections: Int,
        backoffAllows: Boolean,
    ): Boolean {
        if (remotePeerId == localPeerId || hasLinkOrPending || !backoffAllows) return false
        if (openConnections >= maxConnections) return false
        if (lastLostMs != null && nowMs - lastLostMs < reconnectCooldownMs) return false
        val waitingSince = maxOf(firstSeenMs, lastLostMs ?: firstSeenMs)
        return localPeerId < remotePeerId || nowMs - waitingSince >= fallbackAfterMs
    }

    /** First-sighting time of the current visit: [nowMs] for a new peer or one back after [absenceGapMs]. */
    fun sightingStart(
        firstSeenMs: Long?,
        lastSeenMs: Long?,
        nowMs: Long,
    ): Long = if (firstSeenMs == null || lastSeenMs == null || nowMs - lastSeenMs > absenceGapMs) nowMs else firstSeenMs

    fun acceptInbound(openConnections: Int): Boolean = openConnections < maxConnections
}
