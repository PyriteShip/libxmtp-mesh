package org.xmtp.android.library.mesh.policy

/**
 * The advert's service data, `version 2 ‖ flags ‖ token(8)` (DESIGN.md §B14.2). The radio
 * advertises exactly what the node's `advertState` returns and hands every seen v2 advert to
 * `classifyAdvert`; it never builds or matches a token itself.
 */
object ServiceData {
    const val VERSION = 2
    const val TOKEN_BYTES = 8
    const val SIZE = 2 + TOKEN_BYTES
    const val FLAG_PAIRING = 0x01
    const val FLAG_RELAY = 0x02

    /** Only exact v2 adverts; a mesh.10 phone's v1 advert (a short id) is never dialed. */
    fun isV2(b: ByteArray?): Boolean = b != null && b.size == SIZE && (b[0].toInt() and 0xFF) == VERSION

    fun pairing(b: ByteArray): Boolean = (b[1].toInt() and FLAG_PAIRING) != 0

    fun relayOffered(b: ByteArray): Boolean = (b[1].toInt() and FLAG_RELAY) != 0

    fun token(b: ByteArray): ByteArray = b.copyOfRange(2, SIZE)

    /** The first 4 token bytes in hex, for logs: public on the air, never next to an inbox. */
    fun hexPrefix(token: ByteArray): String = token.take(4).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
