package org.xmtp.android.library.mesh.link

/**
 * Android allows one outstanding GATT write/notification per connection.
 * [submit] starts one (false = stack busy, retried shortly). The caller reports
 * completion via [onWriteComplete]; a missing callback is assumed after [completionTimeoutMs].
 */
class WriteQueue(
    private val scheduler: Scheduler,
    private val submit: (ByteArray) -> Boolean,
    private val onOverflow: () -> Unit,
    private val maxQueued: Int = 256,
    private val completionTimeoutMs: Long = 2_000,
    private val busyRetryMs: Long = 10,
) {
    private val queue = ArrayDeque<ByteArray>()
    private var inFlight: Cancellable? = null
    private var retry: Cancellable? = null
    private var closed = false

    fun offer(packet: ByteArray) {
        if (closed) return
        if (queue.size >= maxQueued) {
            onOverflow()
            return
        }
        queue.addLast(packet)
        drain()
    }

    fun onWriteComplete() {
        inFlight?.cancel()
        inFlight = null
        drain()
    }

    fun close() {
        closed = true
        queue.clear()
        inFlight?.cancel()
        retry?.cancel()
        inFlight = null
        retry = null
    }

    private fun drain() {
        if (closed || inFlight != null || retry != null) return
        val next = queue.firstOrNull() ?: return
        if (submit(next)) {
            queue.removeFirst()
            inFlight =
                scheduler.schedule(completionTimeoutMs) {
                    inFlight = null
                    drain()
                }
        } else {
            retry =
                scheduler.schedule(busyRetryMs) {
                    retry = null
                    drain()
                }
        }
    }
}
