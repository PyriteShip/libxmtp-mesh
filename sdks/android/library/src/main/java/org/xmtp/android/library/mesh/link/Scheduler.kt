package org.xmtp.android.library.mesh.link

fun interface Cancellable {
    fun cancel()
}

/** Single-threaded timer source. The radio uses a Handler; tests use a virtual clock. */
interface Scheduler {
    fun nowMs(): Long

    fun schedule(
        delayMs: Long,
        task: () -> Unit,
    ): Cancellable
}
