package org.xmtp.android.library.mesh.link

object LinkLimits {
    /**
     * Largest frame the link carries. Must equal `xmtp_mesh::MAX_FRAME_LEN` (1 MiB).
     * A compile-time constant because the pure layers cannot load the native library;
     * `MeshRadio.start()` compares it with the uniffi export `meshMaxFrameLen()`.
     */
    const val MAX_FRAME_BYTES = 1024 * 1024

    /** ATT payload at the default MTU of 23. */
    const val MIN_ATT_PAYLOAD = 20
    const val MIN_CHUNK_PAYLOAD = MIN_ATT_PAYLOAD - LinkPacket.DATA_HEADER_BYTES

    /**
     * DATA `index`/`count` are u16. ceil(MAX_FRAME_BYTES / MIN_CHUNK_PAYLOAD) = 80,660
     * does not fit, so the u16 limit is the chunk budget.
     */
    const val MAX_CHUNKS = 0xFFFF

    /** Largest frame that fits the chunk budget at [maxPacketBytes] (ATT payload = MTU − 3). */
    fun maxFrameForPacket(maxPacketBytes: Int): Int =
        minOf(MAX_FRAME_BYTES, MAX_CHUNKS * (maxPacketBytes - LinkPacket.DATA_HEADER_BYTES))
}
