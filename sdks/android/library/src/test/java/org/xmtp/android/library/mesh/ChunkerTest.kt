package org.xmtp.android.library.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.link.Chunker
import org.xmtp.android.library.mesh.link.LinkPacket
import kotlin.random.Random

class ChunkerTest {
    private fun payloads(chunks: List<ByteArray>): ByteArray =
        chunks.map { (LinkPacket.decode(it) as LinkPacket.Data).payload }.reduce { a, b -> a + b }

    @Test
    fun splits_into_packets_no_larger_than_max() {
        val frame = Random(1).nextBytes(1000)
        val chunks = Chunker.chunk(7, frame, maxPacketBytes = 20)
        assertEquals(77, chunks.size) // 13 payload bytes per 20-byte packet
        assertTrue(chunks.all { it.size <= 20 })
        chunks.forEachIndexed { i, bytes ->
            val d = LinkPacket.decode(bytes) as LinkPacket.Data
            assertEquals(7, d.msgId)
            assertEquals(i, d.index)
            assertEquals(77, d.count)
        }
        assertArrayEquals(frame, payloads(chunks))
    }

    @Test
    fun exact_multiple_has_no_empty_tail() {
        val frame = ByteArray(26) { it.toByte() }
        val chunks = Chunker.chunk(0, frame, maxPacketBytes = 20)
        assertEquals(2, chunks.size)
        assertArrayEquals(frame, payloads(chunks))
    }

    @Test
    fun large_mtu_sends_small_frame_in_one_packet() {
        val chunks = Chunker.chunk(1, ByteArray(300) { 1 }, maxPacketBytes = 514)
        assertEquals(1, chunks.size)
        assertEquals(307, chunks[0].size)
    }

    @Test
    fun empty_frame_is_rejected() {
        assertThrows(IllegalArgumentException::class.java) { Chunker.chunk(0, ByteArray(0), 20) }
    }
}
