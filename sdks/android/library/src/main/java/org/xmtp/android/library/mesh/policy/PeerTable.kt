package org.xmtp.android.library.mesh.policy

import java.util.concurrent.atomic.AtomicLong

/**
 * The Rust PeerId of each open link. Every link gets a fresh PeerId "p#<n>", never reused in
 * this process (xmtp_mesh MeshTransport contract). There is no stable peer identity any more
 * (DESIGN.md §B14): two links to one phone are both reported, and the node keeps one.
 */
class PeerTable {
    enum class Role { CENTRAL, PERIPHERAL }

    private val byKey = HashMap<String, String>()
    private val byPeerId = HashMap<String, String>()

    /** The link on GATT connection [key] is up: its PeerId (the same one if already reported). */
    fun onLinkReady(key: String): String {
        byKey[key]?.let { return it }
        val peerId = "p#${NEXT_CONNECTION.getAndIncrement()}"
        byKey[key] = peerId
        byPeerId[peerId] = key
        return peerId
    }

    /** The PeerId to report lost, or null if [key] never became ready. */
    fun onLinkClosed(key: String): String? {
        val peerId = byKey.remove(key) ?: return null
        byPeerId.remove(peerId)
        return peerId
    }

    fun keyForPeerId(peerId: String): String? = byPeerId[peerId]

    fun peerIdOf(key: String): String? = byKey[key]

    fun peers(): Set<String> = byPeerId.keys.toSet()

    val size: Int get() = byKey.size

    companion object {
        /** Process-wide, so ids never repeat across radio restarts. */
        private val NEXT_CONNECTION = AtomicLong(1)
    }
}
