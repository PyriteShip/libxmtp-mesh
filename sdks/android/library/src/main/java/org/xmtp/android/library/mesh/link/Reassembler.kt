package org.xmtp.android.library.mesh.link

/**
 * Rebuilds frames from DATA chunks. Bounded: at most [maxPartials] frames in
 * progress, each at most [maxFrameBytes], and forgotten after [staleMs] with no progress.
 */
class Reassembler(
    private val maxFrameBytes: Int,
    private val maxPartials: Int = 2,
    private val staleMs: Long = 30_000,
    private val rememberCompleted: Int = 64,
) {
    sealed interface Result {
        /** Acknowledge the chunk; [frame] is non-null exactly once per completed frame. */
        class Ack(
            val frame: ByteArray?,
        ) : Result

        /** Do not acknowledge; the sender will give up and drop the link. */
        object Reject : Result
    }

    private class Partial(
        val count: Int,
    ) {
        val parts = arrayOfNulls<ByteArray>(count)
        var received = 0
        var bytes = 0
        var lastProgressMs = 0L
    }

    private val partials = LinkedHashMap<Int, Partial>()
    private val completed = ArrayDeque<Int>()
    private val maxChunks =
        minOf(LinkLimits.MAX_CHUNKS, (maxFrameBytes + LinkLimits.MIN_CHUNK_PAYLOAD - 1) / LinkLimits.MIN_CHUNK_PAYLOAD)

    fun accept(
        packet: LinkPacket.Data,
        nowMs: Long,
    ): Result {
        // decode() already rejects these; a Data constructed directly must not throw.
        if (packet.count <= 0 || packet.index < 0 || packet.index >= packet.count) return Result.Reject
        evictStale(nowMs)
        if (packet.msgId in completed) return Result.Ack(null)
        if (packet.count > maxChunks) return Result.Reject
        val partial = partials[packet.msgId] ?: newPartial(packet.msgId, packet.count)
        if (partial.count != packet.count) {
            partials.remove(packet.msgId)
            return Result.Reject
        }
        if (partial.parts[packet.index] == null) {
            if (partial.bytes + packet.payload.size > maxFrameBytes) {
                partials.remove(packet.msgId)
                return Result.Reject
            }
            partial.parts[packet.index] = packet.payload
            partial.received++
            partial.bytes += packet.payload.size
        }
        partial.lastProgressMs = nowMs
        if (partial.received < partial.count) return Result.Ack(null)

        partials.remove(packet.msgId)
        completed.addLast(packet.msgId)
        if (completed.size > rememberCompleted) completed.removeFirst()
        val frame = ByteArray(partial.bytes)
        var offset = 0
        for (part in partial.parts) {
            part!!.copyInto(frame, offset)
            offset += part.size
        }
        return Result.Ack(frame)
    }

    private fun newPartial(
        msgId: Int,
        count: Int,
    ): Partial {
        if (partials.size >= maxPartials) {
            val oldest = partials.entries.minByOrNull { it.value.lastProgressMs }!!.key
            partials.remove(oldest)
        }
        return Partial(count).also { partials[msgId] = it }
    }

    private fun evictStale(nowMs: Long) {
        val it = partials.entries.iterator()
        while (it.hasNext()) {
            if (nowMs - it.next().value.lastProgressMs > staleMs) it.remove()
        }
    }
}
