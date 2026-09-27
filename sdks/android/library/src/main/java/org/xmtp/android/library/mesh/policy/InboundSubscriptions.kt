package org.xmtp.android.library.mesh.policy

/**
 * Which inbound centrals are subscribed to our TX characteristic (one per link key
 * "s:<address>"). Single-threaded: used only on the radio's HandlerThread.
 * A key leaves the set when the central unsubscribes, disconnects, or when the radio
 * closes that link ([forget]).
 */
class InboundSubscriptions {
    private val keys = HashSet<String>()

    /** True when this enable starts a new link. */
    fun enable(key: String): Boolean = keys.add(key)

    /** True when the key was subscribed (the link is over). */
    fun disable(key: String): Boolean = keys.remove(key)

    /** True when the key was subscribed (the link is over). */
    fun disconnected(key: String): Boolean = keys.remove(key)

    /** The radio closed this link; a later enable from the same central is a new link. */
    fun forget(key: String) {
        keys.remove(key)
    }

    fun contains(key: String): Boolean = key in keys

    fun clear() = keys.clear()
}
