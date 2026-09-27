package org.xmtp.android.library.mesh.link

object Chunker {
    /** Encoded DATA packets for [frame], each at most [maxPacketBytes] (ATT payload = MTU − 3). */
    fun chunk(
        msgId: Int,
        frame: ByteArray,
        maxPacketBytes: Int,
    ): List<ByteArray> {
        require(frame.isNotEmpty()) { "empty frame" }
        require(maxPacketBytes > LinkPacket.DATA_HEADER_BYTES) { "packet size $maxPacketBytes too small" }
        val per = maxPacketBytes - LinkPacket.DATA_HEADER_BYTES
        val count = (frame.size + per - 1) / per
        require(count <= 0xFFFF) { "frame needs $count chunks" }
        return List(count) { i ->
            val end = minOf(frame.size, (i + 1) * per)
            LinkPacket.Data(msgId and 0xFFFF, i, count, frame.copyOfRange(i * per, end)).encode()
        }
    }
}
