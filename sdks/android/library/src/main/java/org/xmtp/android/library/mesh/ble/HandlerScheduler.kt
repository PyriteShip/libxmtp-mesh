package org.xmtp.android.library.mesh.ble

import android.os.Handler
import android.os.SystemClock
import org.xmtp.android.library.mesh.link.Cancellable
import org.xmtp.android.library.mesh.link.Scheduler

internal class HandlerScheduler(
    private val handler: Handler,
) : Scheduler {
    override fun nowMs(): Long = SystemClock.elapsedRealtime()

    override fun schedule(
        delayMs: Long,
        task: () -> Unit,
    ): Cancellable {
        val runnable = Runnable(task)
        handler.postDelayed(runnable, delayMs)
        return Cancellable { handler.removeCallbacks(runnable) }
    }
}
