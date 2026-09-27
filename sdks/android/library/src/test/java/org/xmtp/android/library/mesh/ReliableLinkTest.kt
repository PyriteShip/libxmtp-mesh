package org.xmtp.android.library.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.link.LinkConfig
import org.xmtp.android.library.mesh.link.LinkLimits
import org.xmtp.android.library.mesh.link.LinkListener
import org.xmtp.android.library.mesh.link.LinkPacket
import org.xmtp.android.library.mesh.link.ReliableLink
import kotlin.random.Random

class ReliableLinkTest {
    private val idA = ByteArray(8) { 0x0A }
    private val idB = ByteArray(8) { 0x0B }

    private class Recorder : LinkListener {
        var ready: LinkPacket.Hello? = null
        val frames = mutableListOf<ByteArray>()
        val closed = mutableListOf<String>()
        val probeAcks = mutableListOf<Int>()

        override fun onReady(remote: LinkPacket.Hello) {
            ready = remote
        }

        override fun onFrame(frame: ByteArray) {
            frames += frame
        }

        override fun onProbeAck(nonce: Int) {
            probeAcks += nonce
        }

        override fun onClosed(reason: String) {
            closed += reason
        }
    }

    /** Central `a` and peripheral `b` joined by a 1 ms pipe; drop predicates see decoded packets. */
    private inner class LinkPair(
        window: Int = 4,
        maxPacket: Int = 20,
        val dropAtoB: (LinkPacket) -> Boolean = { false },
        val dropBtoA: (LinkPacket) -> Boolean = { false },
    ) {
        val scheduler = FakeScheduler()
        val recA = Recorder()
        val recB = Recorder()
        val sentByA = mutableListOf<LinkPacket>()
        val sentByB = mutableListOf<LinkPacket>()
        lateinit var a: ReliableLink
        lateinit var b: ReliableLink

        init {
            a =
                ReliableLink(
                    config = LinkConfig(idA, maxPacket, window = window),
                    isCentral = true,
                    scheduler = scheduler,
                    write = { bytes ->
                        val p = LinkPacket.decode(bytes)!!
                        sentByA += p
                        if (!dropAtoB(p)) scheduler.schedule(1) { b.onPacket(bytes) }
                    },
                    listener = recA,
                )
            b =
                ReliableLink(
                    config = LinkConfig(idB, maxPacket, window = window),
                    isCentral = false,
                    scheduler = scheduler,
                    write = { bytes ->
                        val p = LinkPacket.decode(bytes)!!
                        sentByB += p
                        if (!dropBtoA(p)) scheduler.schedule(1) { a.onPacket(bytes) }
                    },
                    listener = recB,
                )
        }

        fun start() {
            b.start()
            a.start()
            scheduler.advanceBy(10)
        }
    }

    private fun lone(
        isCentral: Boolean,
        maxQueuedBytes: Int = 64 * LinkLimits.MAX_FRAME_BYTES,
    ): Triple<ReliableLink, Recorder, MutableList<ByteArray>> {
        val rec = Recorder()
        val written = mutableListOf<ByteArray>()
        val config = LinkConfig(idB, 20, maxQueuedBytes = maxQueuedBytes)
        val link = ReliableLink(config, isCentral, FakeScheduler(), { written += it }, rec)
        link.start()
        return Triple(link, rec, written)
    }

    /** A lone link whose [write] calls `close("overflow")` from its [closeOnCall]th call onwards. */
    private class Reentrant(
        isCentral: Boolean,
        closeOnCall: Int,
        config: LinkConfig,
    ) {
        val scheduler = FakeScheduler()
        val rec = Recorder()
        val written = mutableListOf<LinkPacket>()
        lateinit var link: ReliableLink

        init {
            link =
                ReliableLink(config, isCentral, scheduler, { bytes ->
                    written += LinkPacket.decode(bytes)!!
                    if (written.size >= closeOnCall) link.close("overflow")
                }, rec)
        }

        fun assertClosedOnceThenSilent(expectedWrites: Int) {
            assertEquals(listOf("overflow"), rec.closed)
            assertEquals(ReliableLink.State.CLOSED, link.state)
            assertEquals(expectedWrites, written.size)
            assertTrue(written.last() is LinkPacket.Bye)
            scheduler.advanceBy(60_000)
            assertEquals(expectedWrites, written.size)
            assertEquals(listOf("overflow"), rec.closed)
        }
    }

    private val helloFromA = LinkPacket.Hello(LinkPacket.LINK_VERSION, idA, 0, 4).encode()

    @Test
    fun close_inside_hello_write_does_not_resurrect_link() {
        val r = Reentrant(isCentral = false, closeOnCall = 1, config = LinkConfig(idB, 20))
        r.link.start()
        r.link.onPacket(helloFromA)
        assertEquals(null, r.rec.ready)
        r.assertClosedOnceThenSilent(expectedWrites = 2) // HELLO, BYE
    }

    @Test
    fun close_inside_ack_write_does_not_deliver_frame() {
        val r = Reentrant(isCentral = false, closeOnCall = 2, config = LinkConfig(idB, 20))
        r.link.start()
        r.link.onPacket(helloFromA)
        r.link.onPacket(LinkPacket.Data(0, 0, 1, byteArrayOf(1)).encode())
        assertTrue(r.rec.frames.isEmpty())
        r.assertClosedOnceThenSilent(expectedWrites = 3) // HELLO, ACK, BYE
    }

    @Test
    fun close_inside_chunk_write_stops_pump() {
        val r = Reentrant(isCentral = true, closeOnCall = 3, config = LinkConfig(idA, 20))
        r.link.start()
        r.link.onPacket(LinkPacket.Hello(LinkPacket.LINK_VERSION, idB, 0, 4).encode())
        assertTrue(r.link.send(Random(7).nextBytes(100))) // 8 chunks, window 4
        r.assertClosedOnceThenSilent(expectedWrites = 4) // HELLO, DATA 0, DATA 1, BYE
    }

    @Test
    fun close_inside_retransmit_write_stops_timers() {
        val r = Reentrant(isCentral = true, closeOnCall = 3, config = LinkConfig(idA, 20))
        r.link.start()
        r.link.onPacket(LinkPacket.Hello(LinkPacket.LINK_VERSION, idB, 0, 4).encode())
        assertTrue(r.link.send(ByteArray(10) { 1 })) // one chunk
        assertEquals(2, r.written.size)
        r.scheduler.advanceBy(1_500) // retransmission is the 3rd write
        r.assertClosedOnceThenSilent(expectedWrites = 4) // HELLO, DATA, DATA, BYE
    }

    @Test
    fun queue_past_soft_cap_holds_frames_and_stays_open() {
        val (link, rec, _) = lone(isCentral = true, maxQueuedBytes = 100) // never READY
        assertTrue(link.send(ByteArray(60)))
        assertTrue(link.send(ByteArray(40)))
        assertFalse(link.overQueueCap)
        assertTrue(link.send(ByteArray(1)))
        assertTrue(link.overQueueCap)
        assertEquals(ReliableLink.State.HANDSHAKE, link.state)
        assertTrue(rec.closed.isEmpty())
    }

    @Test
    fun queue_cap_frees_as_frames_are_sent() {
        val rec = Recorder()
        val link = ReliableLink(LinkConfig(idA, 20, maxQueuedBytes = 100), true, FakeScheduler(), {}, rec)
        link.start()
        link.onPacket(LinkPacket.Hello(LinkPacket.LINK_VERSION, idB, 0, 4).encode())
        assertTrue(link.send(ByteArray(60) { 1 })) // msg 0 goes straight into flight (5 chunks)
        assertTrue(link.send(ByteArray(60) { 2 })) // queued: 60
        assertTrue(link.send(ByteArray(41) { 3 })) // queued: 101
        assertTrue(link.overQueueCap)
        (0 until 5).forEach { link.onPacket(LinkPacket.Ack(0, it).encode()) } // msg 1 dequeued
        assertFalse(link.overQueueCap)
    }

    /**
     * The node pushes a whole backlog at once (e.g. five inline images).
     * A full queue must hold the frames, not close the link, or every session repeats the burst.
     */
    @Test
    fun burst_of_six_900k_frames_is_delivered_in_order() {
        val p = LinkPair(maxPacket = 514)
        p.start()
        val frames = (1..6).map { Random(100 + it).nextBytes(900_000) }
        frames.forEach { assertTrue(p.a.send(it)) }
        p.scheduler.advanceBy(60_000)
        assertTrue(p.recA.closed.isEmpty())
        assertTrue(p.recB.closed.isEmpty())
        assertEquals(ReliableLink.State.READY, p.a.state)
        assertEquals(frames.size, p.recB.frames.size)
        frames.zip(p.recB.frames).forEach { (sent, got) -> assertArrayEquals(sent, got) }
    }

    @Test
    fun handshake_reports_remote_short_id_on_both_sides() {
        val p = LinkPair()
        p.start()
        assertArrayEquals(idB, p.recA.ready!!.shortId)
        assertArrayEquals(idA, p.recB.ready!!.shortId)
        assertEquals(ReliableLink.State.READY, p.a.state)
        assertEquals(ReliableLink.State.READY, p.b.state)
    }

    @Test
    fun frames_round_trip_in_both_directions() {
        val p = LinkPair()
        p.start()
        val big = Random(1).nextBytes(1000)
        val small = Random(2).nextBytes(50)
        assertTrue(p.a.send(big))
        assertTrue(p.b.send(small))
        p.scheduler.advanceBy(10_000)
        assertArrayEquals(big, p.recB.frames.single())
        assertArrayEquals(small, p.recA.frames.single())
    }

    @Test
    fun frames_are_delivered_in_send_order() {
        val p = LinkPair()
        p.start()
        // Largest first: interleaved sending would complete the smaller frames earlier.
        val frames = (5 downTo 1).map { Random(it).nextBytes(it * 37) }
        frames.forEach { assertTrue(p.a.send(it)) }
        p.scheduler.advanceBy(30_000)
        assertEquals(frames.size, p.recB.frames.size)
        frames.zip(p.recB.frames).forEach { (sent, got) -> assertArrayEquals(sent, got) }
        val msgIds = p.sentByA.filterIsInstance<LinkPacket.Data>().map { it.msgId }
        assertEquals(msgIds.sorted(), msgIds) // no DATA of frame n+1 before all of frame n
    }

    @Test
    fun lost_chunk_is_retransmitted() {
        var dropped = false
        val p =
            LinkPair(dropAtoB = { pkt ->
                if (!dropped && pkt is LinkPacket.Data && pkt.index == 2) {
                    dropped = true
                    true
                } else {
                    false
                }
            })
        p.start()
        val frame = Random(3).nextBytes(100) // 8 chunks at 13 bytes
        p.a.send(frame)
        p.scheduler.advanceBy(10_000)
        assertArrayEquals(frame, p.recB.frames.single())
        assertEquals(2, p.sentByA.count { it is LinkPacket.Data && it.index == 2 })
    }

    @Test
    fun lost_ack_duplicates_chunk_but_delivers_once() {
        var dropped = false
        val p =
            LinkPair(dropBtoA = { pkt ->
                if (!dropped && pkt is LinkPacket.Ack) {
                    dropped = true
                    true
                } else {
                    false
                }
            })
        p.start()
        p.a.send(Random(4).nextBytes(10)) // one chunk
        p.scheduler.advanceBy(10_000)
        assertEquals(1, p.recB.frames.size)
        assertEquals(2, p.sentByA.count { it is LinkPacket.Data })
        assertEquals(2, p.sentByB.count { it is LinkPacket.Ack })
        assertTrue(p.recA.closed.isEmpty())
    }

    @Test
    fun window_limits_in_flight_chunks() {
        val p = LinkPair(window = 4, dropBtoA = { it is LinkPacket.Ack })
        p.start()
        p.a.send(Random(5).nextBytes(200)) // 16 chunks
        p.scheduler.advanceBy(100) // well before the 1.5 s ack timeout
        assertEquals(4, p.sentByA.count { it is LinkPacket.Data })
    }

    @Test
    fun silent_peer_closes_link_after_retries() {
        val p = LinkPair(dropAtoB = { it is LinkPacket.Data })
        p.start()
        p.a.send(ByteArray(10) { 1 })
        p.scheduler.advanceBy(1_500L * 6 + 100)
        assertEquals(listOf("ack timeout"), p.recA.closed)
        assertEquals(listOf("remote bye"), p.recB.closed)
        assertEquals(6, p.sentByA.count { it is LinkPacket.Data }) // first send + 5 retries
        assertFalse(p.a.send(ByteArray(1)))
    }

    @Test
    fun hello_timeout_closes_link() {
        val p = LinkPair(dropAtoB = { true })
        p.start()
        p.scheduler.advanceBy(5_000)
        assertEquals(listOf("hello timeout"), p.recA.closed)
        assertEquals(listOf("hello timeout"), p.recB.closed)
    }

    @Test
    fun frames_queued_before_ready_are_sent_after_handshake() {
        val p = LinkPair()
        val frame = Random(6).nextBytes(40)
        assertTrue(p.a.send(frame))
        p.start()
        p.scheduler.advanceBy(10_000)
        assertArrayEquals(frame, p.recB.frames.single())
    }

    @Test
    fun empty_and_oversize_frames_are_refused() {
        val p = LinkPair()
        p.start()
        assertFalse(p.a.send(ByteArray(0)))
        assertFalse(p.a.send(ByteArray(LinkLimits.MAX_FRAME_BYTES + 1)))
    }

    @Test
    fun frame_over_the_u16_chunk_budget_is_refused_not_thrown() {
        val small = LinkPair(maxPacket = 20) // 13 payload bytes per chunk
        small.start()
        assertFalse(small.a.send(ByteArray(LinkLimits.MAX_CHUNKS * 13 + 1)))
        val large = LinkPair(maxPacket = 514)
        large.start()
        assertTrue(large.a.send(ByteArray(LinkLimits.MAX_FRAME_BYTES)))
    }

    @Test
    fun data_before_hello_is_ignored() {
        val (link, rec, written) = lone(isCentral = false)
        link.onPacket(LinkPacket.Data(0, 0, 1, byteArrayOf(1)).encode())
        assertTrue(rec.frames.isEmpty())
        assertTrue(written.isEmpty())
    }

    @Test
    fun unknown_link_version_closes_with_bye() {
        val (link, rec, written) = lone(isCentral = false)
        link.onPacket(LinkPacket.Hello(2, idA, 0, 4).encode())
        assertEquals(listOf("link version 2"), rec.closed)
        assertTrue(LinkPacket.decode(written.single()) is LinkPacket.Bye)
    }

    @Test
    fun close_sends_bye_and_remote_closes() {
        val p = LinkPair()
        p.start()
        p.a.close("done")
        p.scheduler.advanceBy(10)
        assertEquals(listOf("done"), p.recA.closed)
        assertEquals(listOf("remote bye"), p.recB.closed)
    }

    @Test
    fun probe_is_echoed() {
        val p = LinkPair()
        p.start()
        p.a.sendProbe(7)
        p.scheduler.advanceBy(10)
        assertEquals(listOf(7), p.recA.probeAcks)
    }

    // ---- idle liveness (D23) ------------------------------------------------

    @Test
    fun half_open_link_closes_within_the_liveness_timeout() {
        // The handshake completes normally, then b goes silent (as if its process died):
        // nothing more, not even a keepalive reply, reaches a. a must close on its own.
        var bGoneSilent = false
        val p = LinkPair(dropBtoA = { bGoneSilent })
        p.start()
        assertEquals(ReliableLink.State.READY, p.a.state)
        assertTrue(p.recA.closed.isEmpty())
        bGoneSilent = true
        p.scheduler.advanceBy(24_000)
        assertEquals(listOf("liveness timeout"), p.recA.closed)
    }

    @Test
    fun a_quiet_but_live_link_survives_past_the_liveness_timeout_on_keepalives() {
        // Neither side sends application data, but both are alive and echo Probe/ProbeAck
        // (as any deployed peer already does), so the link must not be closed as "dead".
        // Assert the round trips actually happened: without a real keepalive ping, this
        // test would also pass on a version that simply never times out anything, so the
        // survival alone doesn't prove the keepalive fired.
        val p = LinkPair()
        p.start()
        p.scheduler.advanceBy(60_000)
        assertTrue(p.recA.closed.isEmpty())
        assertTrue(p.recB.closed.isEmpty())
        assertEquals(ReliableLink.State.READY, p.a.state)
        assertEquals(ReliableLink.State.READY, p.b.state)
        assertTrue("a never got a keepalive ProbeAck", p.recA.probeAcks.isNotEmpty())
        assertTrue("b never got a keepalive ProbeAck", p.recB.probeAcks.isNotEmpty())
        assertTrue("a never sent a keepalive Probe", p.sentByA.any { it is LinkPacket.Probe })
        assertTrue("b never sent a keepalive Probe", p.sentByB.any { it is LinkPacket.Probe })
    }

    @Test
    fun inbound_data_traffic_resets_the_liveness_clock() {
        val p = LinkPair()
        p.start()
        p.scheduler.advanceBy(20_000) // keepalive pings and pongs only so far
        assertTrue(p.recA.closed.isEmpty())
        val frame = Random(9).nextBytes(20)
        assertTrue(p.a.send(frame))
        p.scheduler.advanceBy(10_000) // real traffic just refreshed the clock; must not close
        assertTrue(p.recA.closed.isEmpty())
        assertArrayEquals(frame, p.recB.frames.single())
    }

    @Test
    fun an_older_peer_ignores_an_unrecognized_packet_type_instead_of_crashing() {
        // Simulates a peer that predates a hypothetical future packet type: decode() returns
        // null for it, and onPacket already drops anything it can't decode without acting on it.
        val (link, rec, written) = lone(isCentral = false)
        link.onPacket(LinkPacket.Hello(LinkPacket.LINK_VERSION, idA, 0, 4).encode())
        val before = written.size
        link.onPacket(byteArrayOf(0x7F, 0x01, 0x02))
        assertEquals(before, written.size)
        assertTrue(rec.closed.isEmpty())
        assertEquals(ReliableLink.State.READY, link.state)
    }
}
