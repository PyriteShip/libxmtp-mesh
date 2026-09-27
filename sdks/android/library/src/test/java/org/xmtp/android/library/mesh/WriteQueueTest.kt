package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test
import org.xmtp.android.library.mesh.link.WriteQueue

class WriteQueueTest {
    private val scheduler = FakeScheduler()
    private val submitted = mutableListOf<ByteArray>()
    private var busy = false
    private var overflowed = 0
    private val queue =
        WriteQueue(
            scheduler,
            submit = { packet ->
                if (busy) {
                    false
                } else {
                    submitted += packet
                    true
                }
            },
            onOverflow = { overflowed++ },
            maxQueued = 3,
        )

    @Test
    fun one_write_in_flight_until_complete() {
        queue.offer(byteArrayOf(1))
        queue.offer(byteArrayOf(2))
        assertEquals(1, submitted.size)
        queue.onWriteComplete()
        assertEquals(2, submitted.size)
    }

    @Test
    fun busy_submit_is_retried() {
        busy = true
        queue.offer(byteArrayOf(1))
        assertEquals(0, submitted.size)
        busy = false
        scheduler.advanceBy(10)
        assertEquals(1, submitted.size)
    }

    @Test
    fun missing_completion_callback_times_out() {
        queue.offer(byteArrayOf(1))
        queue.offer(byteArrayOf(2))
        scheduler.advanceBy(2_000)
        assertEquals(2, submitted.size)
    }

    @Test
    fun overflow_is_reported() {
        busy = true
        repeat(4) { queue.offer(byteArrayOf(it.toByte())) }
        assertEquals(1, overflowed)
    }

    @Test
    fun close_drops_pending_writes() {
        queue.offer(byteArrayOf(1))
        queue.offer(byteArrayOf(2))
        queue.close()
        queue.onWriteComplete()
        scheduler.advanceBy(5_000)
        assertEquals(1, submitted.size)
    }
}
