package org.xmtp.android.library.mesh.policy

/** What a seen advert is, from the node's `classifyAdvert` (DESIGN.md §B14.2). */
sealed class AdvertMatch {
    /** Not a v2 xmtp-mesh advert, or our own (or our inbox's other installation). */
    object Ignore : AdvertMatch()

    data class Contact(
        val inboxId: String,
        val dialFirst: Boolean,
    ) : AdvertMatch()

    data class Stranger(
        val relayOffered: Boolean,
        val dialFirst: Boolean,
    ) : AdvertMatch()

    /** Both phones are in pairing mode. */
    data class Pairing(
        val dialFirst: Boolean,
    ) : AdvertMatch()
}
