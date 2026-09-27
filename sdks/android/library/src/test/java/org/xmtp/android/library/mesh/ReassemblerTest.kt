package org.xmtp.android.library.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.link.Chunker
import org.xmtp.android.library.mesh.link.LinkLimits
import org.xmtp.android.library.mesh.link.LinkPacket
import org.xmtp.android.library.mesh.link.Reassembler
import org.xmtp.android.library.mesh.link.Reassembler.Result
import kotlin.random.Random

class ReassemblerTest {
    private fun data(
        msgId: Int,
        frame: ByteArray,
        maxPacket: Int = 20,
    ) = Chunker.chunk(msgId, frame, maxPacket).map { LinkPacket.decode(it) as LinkPacket.Data }

    private fun Result.frame(): ByteArray? = (this as Result.Ack).frame

    @Test
    fun out_of_order_chunks_reassemble() {
        val frame = Random(2).nextBytes(100)
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES)
        val parts = data(1, frame).reversed()
        parts.dropLast(1).forEach { assertNull(r.accept(it, 0).frame()) }
        assertArrayEquals(frame, r.accept(parts.last(), 0).frame())
    }

    @Test
    fun duplicate_chunk_is_acked_but_not_double_counted() {
        val frame = Random(3).nextBytes(30)
        val parts = data(1, frame)
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES)
        assertNull(r.accept(parts[0], 0).frame())
        assertNull(r.accept(parts[0], 0).frame())
        assertNull(r.accept(parts[1], 0).frame())
        assertArrayEquals(frame, r.accept(parts[2], 0).frame())
    }

    @Test
    fun chunk_of_completed_message_is_acked_without_redelivery() {
        val parts = data(5, ByteArray(10) { 1 })
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES)
        assertEquals(10, r.accept(parts[0], 0).frame()!!.size)
        val again = r.accept(parts[0], 0)
        assertTrue(again is Result.Ack)
        assertNull(again.frame())
    }

    @Test
    fun max_frame_is_the_rust_limit_and_reassembles_whole() {
        // Must equal xmtp_mesh::MAX_FRAME_LEN (uniffi meshMaxFrameLen(); checked at runtime by MeshRadio.start).
        assertEquals(1 shl 20, LinkLimits.MAX_FRAME_BYTES)
        val frame = Random(4).nextBytes(LinkLimits.MAX_FRAME_BYTES)
        val parts = data(1, frame, maxPacket = 514) // 2,069 chunks of 507 bytes
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES)
        parts.dropLast(1).forEach { assertNull(r.accept(it, 0).frame()) }
        assertArrayEquals(frame, r.accept(parts.last(), 0).frame())
    }

    @Test
    fun u16_chunk_budget_caps_frames_at_minimum_mtu() {
        assertEquals(0xFFFF, LinkLimits.MAX_CHUNKS)
        assertEquals(65_535 * 13, LinkLimits.maxFrameForPacket(20))
        assertEquals(LinkLimits.MAX_FRAME_BYTES, LinkLimits.maxFrameForPacket(514))
    }

    @Test
    fun hostile_chunk_count_is_rejected() {
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES)
        val hostile = LinkPacket.Data(1, 0, LinkLimits.MAX_CHUNKS + 1, byteArrayOf(1))
        assertSame(Result.Reject, r.accept(hostile, 0))
    }

    @Test
    fun directly_constructed_bad_index_or_count_is_rejected_not_thrown() {
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES)
        assertSame(Result.Reject, r.accept(LinkPacket.Data(1, 3, 3, byteArrayOf(1)), 0))
        assertSame(Result.Reject, r.accept(LinkPacket.Data(1, 5, 2, byteArrayOf(1)), 0))
        assertSame(Result.Reject, r.accept(LinkPacket.Data(1, 0, 0, byteArrayOf(1)), 0))
        assertSame(Result.Reject, r.accept(LinkPacket.Data(1, -1, 2, byteArrayOf(1)), 0))
        assertSame(Result.Reject, r.accept(LinkPacket.Data(1, -2, -1, byteArrayOf(1)), 0))
    }

    @Test
    fun frame_over_limit_is_rejected() {
        val r = Reassembler(maxFrameBytes = 100)
        val parts = data(1, ByteArray(150) { 2 }, maxPacket = 57) // 50-byte chunks
        assertNull(r.accept(parts[0], 0).frame())
        assertNull(r.accept(parts[1], 0).frame())
        assertSame(Result.Reject, r.accept(parts[2], 0))
    }

    @Test
    fun count_mismatch_drops_the_partial() {
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES)
        assertNull(r.accept(LinkPacket.Data(9, 0, 3, byteArrayOf(1)), 0).frame())
        assertSame(Result.Reject, r.accept(LinkPacket.Data(9, 1, 4, byteArrayOf(1)), 0))
    }

    @Test
    fun stale_partial_is_evicted() {
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES, staleMs = 30_000)
        val parts = data(1, ByteArray(20) { 3 }) // 2 chunks
        assertNull(r.accept(parts[0], 0).frame())
        // chunk 0 is forgotten after 30 s; chunk 1 alone cannot complete the frame
        assertNull(r.accept(parts[1], 30_001).frame())
    }

    @Test
    fun partial_limit_evicts_least_recent() {
        val r = Reassembler(LinkLimits.MAX_FRAME_BYTES, maxPartials = 2)
        val a = data(1, ByteArray(20) { 1 })
        val b = data(2, ByteArray(20) { 2 })
        val c = data(3, ByteArray(20) { 3 })
        r.accept(a[0], 0)
        r.accept(b[0], 1)
        r.accept(c[0], 2) // evicts msg 1
        assertNull(r.accept(a[1], 3).frame())
        assertEquals(20, r.accept(c[1], 4).frame()!!.size)
    }
}
