package org.xmtp.android.library.mesh.policy

import java.util.concurrent.atomic.AtomicLong

/**
 * One active link per peer, and the Rust PeerId of each active link.
 *
 * A peer is identified by its short id (from the link HELLO), never by its
 * Bluetooth address, which rotates. Rust sees connections, not peers: each
 * link that becomes a peer's active link gets a fresh PeerId "<shortId>#<n>",
 * never reused in this process (xmtp_mesh MeshTransport contract).
 */
class PeerTable(
    private val localShortId: String,
) {
    enum class Role { CENTRAL, PERIPHERAL }

    data class LinkRef(
        val key: String,
        val role: Role,
    )

    /**
     * [closeKey]: a link to close now (maybe the new one).
     * [lostPeerId]: tell Rust this connection is gone; report it before [connectedPeerId].
     * [connectedPeerId]: tell Rust a new connection is up under this PeerId.
     */
    data class Decision(
        val keep: Boolean,
        val closeKey: String?,
        val lostPeerId: String?,
        val connectedPeerId: String?,
    )

    private class Active(
        val link: LinkRef,
        val peerId: String,
    )

    private val active = HashMap<String, Active>() // short id -> active link
    private val byPeerId = HashMap<String, String>() // Rust PeerId -> short id

    /**
     * [existingIsStale]: the peer's current active link (if any) has carried no inbound
     * traffic within a short window — it may be half-open (D23). True skips the role
     * tie-break below and keeps [link] outright, the same way a fresh peer with no existing
     * link is handled.
     */
    fun onLinkReady(
        shortId: String,
        link: LinkRef,
        existingIsStale: Boolean = false,
    ): Decision {
        if (shortId ==
            localShortId
        ) {
            return Decision(keep = false, closeKey = link.key, lostPeerId = null, connectedPeerId = null)
        }
        val existing = active[shortId]
        if (existing == null) {
            return Decision(keep = true, closeKey = null, lostPeerId = null, connectedPeerId = activate(shortId, link))
        }
        if (existing.link.key == link.key) {
            return Decision(keep = true, closeKey = null, lostPeerId = null, connectedPeerId = null)
        }
        if (existingIsStale) {
            byPeerId.remove(existing.peerId)
            return Decision(
                keep = true,
                closeKey = existing.link.key,
                lostPeerId = existing.peerId,
                connectedPeerId = activate(shortId, link),
            )
        }
        val preferred = if (localShortId < shortId) Role.CENTRAL else Role.PERIPHERAL
        return if (link.role == preferred && existing.link.role != preferred) {
            byPeerId.remove(existing.peerId)
            Decision(
                keep = true,
                closeKey = existing.link.key,
                lostPeerId = existing.peerId,
                connectedPeerId = activate(shortId, link),
            )
        } else {
            Decision(keep = false, closeKey = link.key, lostPeerId = null, connectedPeerId = null)
        }
    }

    /** The Rust PeerId to report lost when [key] was [shortId]'s active link; null otherwise. */
    fun onLinkClosed(
        shortId: String,
        key: String,
    ): String? {
        val current = active[shortId] ?: return null
        if (current.link.key != key) return null
        active.remove(shortId)
        byPeerId.remove(current.peerId)
        return current.peerId
    }

    fun activeKey(shortId: String): String? = active[shortId]?.link?.key

    fun peerIdOf(shortId: String): String? = active[shortId]?.peerId

    /** The link carrying Rust connection [peerId], or null once that connection is gone. */
    fun keyForPeerId(peerId: String): String? = byPeerId[peerId]?.let { active[it]?.link?.key }

    fun shortIdOf(peerId: String): String? = byPeerId[peerId]

    fun peers(): Set<String> = active.keys.toSet()

    val size: Int get() = active.size

    private fun activate(
        shortId: String,
        link: LinkRef,
    ): String {
        val peerId = "$shortId#${NEXT_CONNECTION.getAndIncrement()}"
        active[shortId] = Active(link, peerId)
        byPeerId[peerId] = shortId
        return peerId
    }

    companion object {
        /** Process-wide, so ids never repeat across radio restarts. */
        private val NEXT_CONNECTION = AtomicLong(1)

        /**
         * D23: margin on top of 2x the keepalive interval used by
         * [isStale]. A link's own idle-liveness check (see `ReliableLink.onLivenessCheck`) runs
         * on a fixed period, not reset by traffic, so a keepalive probe that becomes due just
         * after one check runs is not sent until close to the next one — the worst-case gap
         * between two inbound packets on a healthy, merely-idle link is therefore just under
         * 2x keepaliveIntervalMs, not 1x. A stale window that isn't comfortably above that bound
         * reads a healthy link as stale, and the two phones — each judging staleness from their
         * own inbound history — can then disagree about which link is stale, each keep a
         * different one, and each send Bye on the link the other kept: both lose the peer.
         */
        const val DUPLICATE_STALE_MARGIN_MS = 4_000L

        /**
         * True when [lastInboundMs] (null counts as stale: no link to compare against) is older
         * than `2 * keepaliveIntervalMs + `[DUPLICATE_STALE_MARGIN_MS] relative to [nowMs]. Pure
         * and deterministic, so both phones — and this class's tests — compute the identical
         * threshold from the identical [keepaliveIntervalMs]; see [DUPLICATE_STALE_MARGIN_MS] for
         * why the margin has to be that large.
         */
        fun isStale(
            lastInboundMs: Long?,
            nowMs: Long,
            keepaliveIntervalMs: Long,
        ): Boolean =
            lastInboundMs == null || nowMs - lastInboundMs >= 2 * keepaliveIntervalMs + DUPLICATE_STALE_MARGIN_MS
    }
}
