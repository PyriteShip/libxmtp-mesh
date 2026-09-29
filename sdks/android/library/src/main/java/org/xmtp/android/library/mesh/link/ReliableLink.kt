package org.xmtp.android.library.mesh.link

class LinkConfig(
    val maxPacketBytes: Int,
    val window: Int = 4,
    val ackTimeoutMs: Long = 1_500,
    val maxRetries: Int = 5,
    val helloTimeoutMs: Long = 5_000,
    val maxFrameBytes: Int = LinkLimits.MAX_FRAME_BYTES,
    val codedHint: Boolean = false,
    /**
     * Soft cap on bytes of frames waiting to be sent: past it [ReliableLink.send] still
     * holds the frame (an ordered pipe must not lose one) and reports [ReliableLink.overQueueCap].
     */
    val maxQueuedBytes: Int = 64 * LinkLimits.MAX_FRAME_BYTES,
    /**
     * Once READY, no more than this long passes without checking for inbound silence.
     * Idle past this long since the last inbound packet, the link pings with a [LinkPacket.Probe]
     * (the same wire packet a coded-PHY probe uses; an older peer already echoes it, see
     * [ReliableLink]'s class doc). Kept short relative to [livenessTimeoutMs] so a genuinely live
     * but quiet peer gets at least one ping-pong round trip before the link gives up on it.
     */
    val keepaliveIntervalMs: Long = 8_000,
    /**
     * Closes the link with reason "liveness timeout" once this long has passed with no inbound
     * packet at all (a half-open link: the transport still reports "connected" but the remote
     * process is gone and nothing detects that on its own). D23.
     */
    val livenessTimeoutMs: Long = 24_000,
) {
    init {
        require(maxPacketBytes >= LinkLimits.MIN_ATT_PAYLOAD) { "packet size below ATT minimum" }
        require(window in 1..MAX_WINDOW) { "window must be 1..$MAX_WINDOW" }
        require(maxQueuedBytes > 0) { "maxQueuedBytes must be positive" }
        require(keepaliveIntervalMs > 0) { "keepaliveIntervalMs must be positive" }
        require(livenessTimeoutMs > keepaliveIntervalMs) { "livenessTimeoutMs must exceed keepaliveIntervalMs" }
    }

    companion object {
        const val MAX_WINDOW = 16
    }
}

interface LinkListener {
    fun onReady(remote: LinkPacket.Hello)

    fun onFrame(frame: ByteArray)

    fun onProbeAck(nonce: Int)

    fun onClosed(reason: String)
}

/**
 * Reliable, ordered frame pipe over one BLE connection.
 * Not thread-safe: call everything on the thread [scheduler] runs tasks on.
 * [write] may call [close] re-entrantly (e.g. on write-queue overflow): every write
 * site re-checks [state] afterwards, and [close] is idempotent.
 *
 * **Idle liveness (D23).** A BLE "connected" callback does not mean the remote
 * process is still there: if it restarts, the transport can keep reporting a link as
 * open with nothing to detect the other end is gone (a half-open link). Once READY,
 * [lastInboundMs] tracks the last time any packet arrived; idle past
 * [LinkConfig.keepaliveIntervalMs] the link pings with a [LinkPacket.Probe] (reusing the
 * wire packet the coded-PHY probe already used for round trips — a peer that predates
 * this change already echoes [LinkPacket.ProbeAck] for it, so this is a ping any deployed
 * peer answers). Idle past [LinkConfig.livenessTimeoutMs] with nothing at all inbound —
 * the peer never answered, or never pinged back — the link closes with reason
 * "liveness timeout". [LinkPacket.decode] returns null for an unrecognized packet type,
 * which [onPacket] already ignores; an *older* peer receiving a packet type introduced
 * after it shipped behaves the same way (drops it silently, no crash, no reply), so a new
 * packet type stays backward compatible if one is ever needed here.
 */
class ReliableLink(
    private val config: LinkConfig,
    private val isCentral: Boolean,
    private val scheduler: Scheduler,
    private val write: (ByteArray) -> Unit,
    private val listener: LinkListener,
) {
    enum class State { HANDSHAKE, READY, CLOSED }

    var state = State.HANDSHAKE
        private set

    private class Outgoing(
        val msgId: Int,
        val chunks: List<ByteArray>,
    ) {
        var nextIndex = 0
        var acked = 0
        val inFlight = HashMap<Int, Cancellable>()
        val retries = HashMap<Int, Int>()
    }

    private val queue = ArrayDeque<ByteArray>()
    private var queuedBytes = 0L
    private var current: Outgoing? = null
    private var nextMsgId = 0
    private var remoteWindow = 1
    private var helloTimer: Cancellable? = null
    private var livenessTimer: Cancellable? = null
    private var keepaliveNonce = 0
    private val reassembler = Reassembler(config.maxFrameBytes)

    /**
     * Wall time (per [scheduler]) of the last packet this link decoded. Updated on every
     * decoded packet, including during HANDSHAKE (a Hello counts too), though the idle-liveness
     * check that reads it only starts once the link reaches READY.
     */
    var lastInboundMs: Long = 0L
        private set

    fun start() {
        check(state == State.HANDSHAKE) { "already started" }
        helloTimer =
            scheduler.schedule(config.helloTimeoutMs) {
                if (state == State.HANDSHAKE) close("hello timeout", sendBye = false)
            }
        if (isCentral) sendHello()
    }

    private val maxSendBytes = minOf(config.maxFrameBytes, LinkLimits.maxFrameForPacket(config.maxPacketBytes))

    /** True while more than [LinkConfig.maxQueuedBytes] of frames wait to be sent. */
    val overQueueCap: Boolean get() = queuedBytes > config.maxQueuedBytes

    /**
     * Queue a whole frame. False only if the link is closed, or the frame is empty or larger
     * than this link can carry (frame limit, or 65,535 chunks at this packet size).
     * A full queue never refuses a frame: every queued byte comes from the local node, which
     * sends in bursts with no flow control, so refusing (and closing the link) would make the
     * next session send the same burst again. Past the soft cap the frame is still held and
     * [overQueueCap] turns true for the caller to log.
     */
    fun send(frame: ByteArray): Boolean {
        if (state == State.CLOSED || frame.isEmpty() || frame.size > maxSendBytes) return false
        queue.addLast(frame)
        queuedBytes += frame.size
        pump()
        return true
    }

    fun sendProbe(nonce: Int) {
        if (state == State.READY) write(LinkPacket.Probe(nonce).encode())
    }

    fun close(
        reason: String,
        sendBye: Boolean = true,
    ) {
        if (state == State.CLOSED) return
        // CLOSED before the BYE write, so a close() re-entered from write() is a no-op.
        state = State.CLOSED
        helloTimer?.cancel()
        livenessTimer?.cancel()
        current?.inFlight?.values?.forEach { it.cancel() }
        current = null
        queue.clear()
        queuedBytes = 0
        if (sendBye) write(LinkPacket.Bye(LinkPacket.BYE_NORMAL).encode())
        listener.onClosed(reason)
    }

    fun onPacket(bytes: ByteArray) {
        if (state == State.CLOSED) return
        val packet = LinkPacket.decode(bytes) ?: return
        lastInboundMs = scheduler.nowMs()
        when (packet) {
            is LinkPacket.Hello -> onHello(packet)
            is LinkPacket.Bye -> close("remote bye", sendBye = false)
            is LinkPacket.Data -> if (state == State.READY) onData(packet)
            is LinkPacket.Ack -> if (state == State.READY) onAck(packet)
            is LinkPacket.Probe -> if (state == State.READY) write(LinkPacket.ProbeAck(packet.nonce).encode())
            is LinkPacket.ProbeAck -> if (state == State.READY) listener.onProbeAck(packet.nonce)
        }
    }

    private fun sendHello() {
        val flags = if (config.codedHint) LinkPacket.FLAG_CODED_HINT else 0
        // The token field stays zero (DESIGN.md §B14.2): the central connects from the adapter's own
        // address, so a token here would tie that address to its adverts across windows.
        write(
            LinkPacket.Hello(LinkPacket.LINK_VERSION, ByteArray(LinkPacket.TOKEN_BYTES), flags, config.window).encode(),
        )
    }

    private fun onHello(hello: LinkPacket.Hello) {
        if (state != State.HANDSHAKE) return
        if (hello.version != LinkPacket.LINK_VERSION) {
            close("link version ${hello.version}", sendBye = true)
            return
        }
        if (!isCentral) {
            sendHello()
            if (state != State.HANDSHAKE) return
        }
        remoteWindow = hello.window.coerceIn(1, LinkConfig.MAX_WINDOW)
        helloTimer?.cancel()
        state = State.READY
        lastInboundMs = scheduler.nowMs()
        scheduleLivenessCheck()
        listener.onReady(hello)
        pump()
    }

    private fun scheduleLivenessCheck() {
        livenessTimer = scheduler.schedule(config.keepaliveIntervalMs) { onLivenessCheck() }
    }

    private fun onLivenessCheck() {
        if (state != State.READY) return
        val idleMs = scheduler.nowMs() - lastInboundMs
        if (idleMs >= config.livenessTimeoutMs) {
            close("liveness timeout", sendBye = true)
            return
        }
        if (idleMs >= config.keepaliveIntervalMs) {
            write(LinkPacket.Probe(nextKeepaliveNonce()).encode())
            // write() may re-entrantly close() (e.g. write-queue overflow); don't resurrect the timer.
            if (state != State.READY) return
        }
        scheduleLivenessCheck()
    }

    private fun nextKeepaliveNonce(): Int {
        val nonce = keepaliveNonce
        keepaliveNonce = (keepaliveNonce + 1) and 0xFFFF
        return nonce
    }

    private fun onData(packet: LinkPacket.Data) {
        when (val result = reassembler.accept(packet, scheduler.nowMs())) {
            is Reassembler.Result.Ack -> {
                write(LinkPacket.Ack(packet.msgId, packet.index).encode())
                if (state != State.READY) return
                result.frame?.let(listener::onFrame)
            }
            Reassembler.Result.Reject -> Unit
        }
    }

    private fun onAck(ack: LinkPacket.Ack) {
        val out = current ?: return
        if (ack.msgId != out.msgId) return
        val timer = out.inFlight.remove(ack.index) ?: return
        timer.cancel()
        out.acked++
        if (out.acked == out.chunks.size) current = null
        pump()
    }

    private fun pump() {
        if (state != State.READY) return
        val out = current ?: nextOutgoing() ?: return
        val window = minOf(config.window, remoteWindow)
        while (state == State.READY && out.inFlight.size < window && out.nextIndex < out.chunks.size) {
            transmit(out, out.nextIndex++)
        }
    }

    private fun nextOutgoing(): Outgoing? {
        val frame = queue.removeFirstOrNull() ?: return null
        queuedBytes -= frame.size
        val out = Outgoing(nextMsgId, Chunker.chunk(nextMsgId, frame, config.maxPacketBytes))
        nextMsgId = (nextMsgId + 1) and 0xFFFF
        current = out
        return out
    }

    private fun transmit(
        out: Outgoing,
        index: Int,
    ) {
        // Timer first: a close() re-entered from write() cancels it with the rest.
        out.inFlight.put(index, scheduler.schedule(config.ackTimeoutMs) { onAckTimeout(out, index) })?.cancel()
        write(out.chunks[index])
    }

    private fun onAckTimeout(
        out: Outgoing,
        index: Int,
    ) {
        if (state != State.READY || current !== out || !out.inFlight.containsKey(index)) return
        val attempts = (out.retries[index] ?: 0) + 1
        if (attempts > config.maxRetries) {
            close("ack timeout", sendBye = true)
            return
        }
        out.retries[index] = attempts
        transmit(out, index)
    }
}
