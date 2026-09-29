package org.xmtp.android.library.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.link.LinkPacket

class LinkPacketTest {
    private val id = ByteArray(8) { (it + 1).toByte() }

    @Test
    fun theHelloCarriesTheAdvertTokenAtVersion2() {
        val token = ByteArray(8) { 9 }
        val hello =
            LinkPacket.decode(
                LinkPacket.Hello(LinkPacket.LINK_VERSION, token, 0, 4).encode(),
            ) as LinkPacket.Hello
        assertEquals(2, hello.version)
        assertArrayEquals(token, hello.token)
    }

    @Test
    fun every_packet_type_round_trips() {
        val hello =
            LinkPacket.decode(
                LinkPacket.Hello(1, id, LinkPacket.FLAG_CODED_HINT, 4).encode(),
            ) as LinkPacket.Hello
        assertEquals(1, hello.version)
        assertArrayEquals(id, hello.token)
        assertTrue(hello.codedHint)
        assertEquals(4, hello.window)

        val data = LinkPacket.decode(LinkPacket.Data(65535, 2, 3, byteArrayOf(9, 8)).encode()) as LinkPacket.Data
        assertEquals(65535, data.msgId)
        assertEquals(2, data.index)
        assertEquals(3, data.count)
        assertArrayEquals(byteArrayOf(9, 8), data.payload)

        assertEquals(LinkPacket.Ack(513, 7), LinkPacket.decode(LinkPacket.Ack(513, 7).encode()))
        assertEquals(LinkPacket.Probe(42), LinkPacket.decode(LinkPacket.Probe(42).encode()))
        assertEquals(LinkPacket.ProbeAck(42), LinkPacket.decode(LinkPacket.ProbeAck(42).encode()))
        assertEquals(LinkPacket.Bye(0), LinkPacket.decode(LinkPacket.Bye(0).encode()))
    }

    @Test
    fun hello_fits_minimum_mtu() {
        assertTrue(LinkPacket.Hello(1, id, 0, 4).encode().size <= 20)
    }

    @Test
    fun malformed_packets_decode_to_null() {
        assertNull(LinkPacket.decode(ByteArray(0)))
        assertNull(LinkPacket.decode(byteArrayOf(0x7F, 1, 2, 3))) // unknown type
        assertNull(LinkPacket.decode(byteArrayOf(0x01, 1, 2, 3))) // truncated hello
        assertNull(LinkPacket.decode(byteArrayOf(0x02, 0, 1, 0, 0, 0, 1))) // data without payload
        assertNull(LinkPacket.decode(byteArrayOf(0x02, 0, 1, 0, 3, 0, 3, 9))) // index == count
        assertNull(LinkPacket.decode(byteArrayOf(0x02, 0, 1, 0, 0, 0, 0, 9))) // count == 0
        assertNull(LinkPacket.decode(byteArrayOf(0x03, 0, 1))) // truncated ack
        assertNull(LinkPacket.decode(byteArrayOf(0x04))) // truncated probe
        assertNull(LinkPacket.decode(byteArrayOf(0x06))) // truncated bye
    }

    @Test
    fun hello_tolerates_trailing_bytes_from_future_versions() {
        val bytes = LinkPacket.Hello(1, id, 0, 4).encode() + byteArrayOf(1, 2, 3)
        assertEquals(4, (LinkPacket.decode(bytes) as LinkPacket.Hello).window)
    }
}
