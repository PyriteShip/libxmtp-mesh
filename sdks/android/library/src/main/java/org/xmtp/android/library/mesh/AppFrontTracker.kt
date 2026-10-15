package org.xmtp.android.library.mesh

/**
 * Counts started activities and calls [onFront] each time the app comes to the front (the
 * count goes from 0 to 1). [startedNow] is the count at creation: [Mesh.start] runs while
 * the app is in front, so it passes 1. Not thread-safe; activity callbacks run on the main
 * thread.
 */
internal class AppFrontTracker(
    startedNow: Int,
    private val onFront: () -> Unit,
) {
    private var started = startedNow

    fun activityStarted() {
        if (started++ == 0) onFront()
    }

    fun activityStopped() {
        // Clamped: an activity that started before the tracker existed can stop after it.
        if (started > 0) started--
    }
}
