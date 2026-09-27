package org.xmtp.android.library.mesh

import org.xmtp.android.library.mesh.link.Cancellable
import org.xmtp.android.library.mesh.link.Scheduler
import java.util.PriorityQueue

/** Deterministic virtual clock: tasks run only inside [advanceBy], in time then FIFO order. */
class FakeScheduler : Scheduler {
    private class Task(
        val at: Long,
        val seq: Long,
        val run: () -> Unit,
    ) {
        var cancelled = false
    }

    private var now = 0L
    private var seq = 0L
    private val tasks = PriorityQueue<Task>(compareBy<Task>({ it.at }, { it.seq }))

    override fun nowMs(): Long = now

    override fun schedule(
        delayMs: Long,
        task: () -> Unit,
    ): Cancellable {
        val t = Task(now + maxOf(0L, delayMs), seq++, task)
        tasks.add(t)
        return Cancellable { t.cancelled = true }
    }

    fun advanceBy(ms: Long) {
        val end = now + ms
        while (true) {
            val next = tasks.peek() ?: break
            if (next.at > end) break
            tasks.poll()
            now = next.at
            if (!next.cancelled) next.run()
        }
        now = end
    }
}
