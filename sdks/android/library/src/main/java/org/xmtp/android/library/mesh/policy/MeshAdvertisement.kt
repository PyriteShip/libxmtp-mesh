package org.xmtp.android.library.mesh.policy

import org.xmtp.android.library.mesh.link.LinkPacket

/**
 * Service data under the xmtp-mesh service UUID (scan response): version, flags, short id.
 * Versioned so rotating tokens (DESIGN.md §B6.3, D9) can replace the short id later.
 */
class MeshAdvertisement(
    val version: Int,
    val flags: Int,
    val shortId: ByteArray,
) {
    val pairingMode: Boolean get() = (flags and FLAG_PAIRING) != 0

    fun encode(): ByteArray = byteArrayOf(version.toByte(), flags.toByte()) + shortId

    companion object {
        const val VERSION = 1
        const val FLAG_PAIRING = 0x01
        const val SIZE = 2 + LinkPacket.SHORT_ID_BYTES

        fun decode(bytes: ByteArray?): MeshAdvertisement? {
            if (bytes == null || bytes.size < SIZE) return null
            if ((bytes[0].toInt() and 0xFF) != VERSION) return null
            return MeshAdvertisement(VERSION, bytes[1].toInt() and 0xFF, bytes.copyOfRange(2, SIZE))
        }
    }
}
