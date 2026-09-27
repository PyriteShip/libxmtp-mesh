package org.xmtp.android.library.mesh.link

import java.security.SecureRandom

/**
 * The 8-byte short id advertised in cleartext (DESIGN.md D9, D22): the logical peer identity
 * (lowercase hex). Rust never sees it alone: its PeerIds are connection-scoped "<hex>#<n>" (PeerTable).
 */
object ShortId {
    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    fun parse(hex: String): ByteArray? {
        if (hex.length != 2 * LinkPacket.SHORT_ID_BYTES) return null
        if (!hex.all { it in '0'..'9' || it in 'a'..'f' }) return null
        return ByteArray(LinkPacket.SHORT_ID_BYTES) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    fun random(): ByteArray = ByteArray(LinkPacket.SHORT_ID_BYTES).also { SecureRandom().nextBytes(it) }
}
