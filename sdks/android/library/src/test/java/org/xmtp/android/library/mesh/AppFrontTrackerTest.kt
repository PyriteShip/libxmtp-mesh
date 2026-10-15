package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test

class AppFrontTrackerTest {
    private var fronts = 0

    private fun tracker(startedNow: Int) = AppFrontTracker(startedNow) { fronts++ }

    @Test
    fun created_in_front_fires_only_after_leaving_and_returning() {
        val t = tracker(1)
        t.activityStarted() // a second activity, or a rotation's new instance
        t.activityStopped()
        assertEquals(0, fronts)
        t.activityStopped() // app goes to the background
        assertEquals(0, fronts)
        t.activityStarted() // back to the front
        assertEquals(1, fronts)
    }

    @Test
    fun fires_once_per_return_to_front() {
        val t = tracker(1)
        repeat(3) {
            t.activityStopped()
            t.activityStarted()
        }
        assertEquals(3, fronts)
    }

    @Test
    fun rotation_while_in_front_does_not_fire() {
        val t = tracker(1)
        // A configuration change starts the new instance before stopping the old one.
        t.activityStarted()
        t.activityStopped()
        assertEquals(0, fronts)
    }

    @Test
    fun extra_stops_clamp_at_zero() {
        val t = tracker(0)
        t.activityStopped()
        t.activityStopped()
        t.activityStarted()
        assertEquals(1, fronts)
        t.activityStarted()
        assertEquals(1, fronts)
    }
}
