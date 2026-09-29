package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.AdvertClock
import org.xmtp.android.library.mesh.policy.AdvertClock.Action

/** The token and the address change together, once per 15-minute window (DESIGN.md §B14.2). */
class AdvertClockTest {
    private fun data(
        flags: Int,
        token: Int,
    ) = byteArrayOf(2, flags.toByte()) + ByteArray(8) { token.toByte() }

    @Test
    fun theFirstStateStartsASet() {
        val c = AdvertClock()
        assertTrue(c.due(nowSecs = 0, version = 0))
        assertEquals(
            Action.NEW_SET,
            c.apply(window = 10, serviceData = data(0, 1), nextWindowAtSecs = 9_900, version = 3),
        )
    }

    /** Never new data on the old set at a window change: that would keep the address across tokens. */
    @Test
    fun aNewWindowAlwaysStartsANewSet() {
        val c = AdvertClock()
        c.apply(10, data(0, 1), 9_900, 3)
        assertFalse(c.due(nowSecs = 9_899, version = 3))
        assertTrue(c.due(nowSecs = 9_900, version = 3))
        assertEquals(Action.NEW_SET, c.apply(11, data(0, 2), 10_800, 3))
    }

    /** Pairing or relay switched inside a window: same token, so the same set (and address) keeps going. */
    @Test
    fun aFlagChangeInsideAWindowKeepsTheSet() {
        val c = AdvertClock()
        c.apply(10, data(0, 1), 9_900, 3)
        assertTrue(c.due(nowSecs = 9_100, version = 4))
        assertEquals(Action.UPDATE_DATA, c.apply(10, data(1, 1), 9_900, 4))
    }

    /** A reset changes the token inside a window: that is a new set too. */
    @Test
    fun aNewTokenInsideAWindowStartsANewSet() {
        val c = AdvertClock()
        c.apply(10, data(0, 1), 9_900, 3)
        assertEquals(Action.NEW_SET, c.apply(10, data(0, 9), 9_900, 4))
    }

    @Test
    fun nothingChangedIsNothingToDo() {
        val c = AdvertClock()
        c.apply(10, data(0, 1), 9_900, 3)
        assertEquals(Action.NONE, c.apply(10, data(0, 1), 9_900, 4))
    }

    @Test
    fun theAlarmAimsAtTheNextWindow() {
        val c = AdvertClock()
        c.apply(10, data(0, 1), 9_900, 3)
        assertEquals(1_000L, c.delayToNextWindowMs(nowMs = 9_899_000))
        assertEquals(0L, c.delayToNextWindowMs(nowMs = 9_950_000))
        c.reset()
        assertTrue(c.due(nowSecs = 0, version = 3))
    }

    /**
     * The clock vouches for "this window, this version" only between its first read in the
     * window and the window's end, and only at the version it read: a cached classification
     * never crosses a window boundary (either way: a clock set back too) or a contacts change.
     */
    @Test
    fun itCoversOnlyItsOwnWindowAndVersion() {
        val c = AdvertClock()
        assertFalse(c.covers(nowSecs = 9_500, version = 3))
        c.apply(10, data(0, 1), 9_900, 3, readAtSecs = 9_100)
        assertTrue(c.covers(nowSecs = 9_100, version = 3))
        assertTrue(c.covers(nowSecs = 9_899, version = 3))
        assertFalse(c.covers(nowSecs = 9_900, version = 3))
        assertFalse(c.covers(nowSecs = 9_099, version = 3))
        assertFalse(c.covers(nowSecs = 9_500, version = 4))
        // A later read in the same window keeps the earliest start.
        c.apply(10, data(0, 1), 9_900, 3, readAtSecs = 9_400)
        assertTrue(c.covers(nowSecs = 9_200, version = 3))
        // A read that does not say when it was made vouches for nothing.
        c.apply(11, data(0, 2), 10_800, 3)
        assertFalse(c.covers(nowSecs = 10_000, version = 3))
        c.apply(12, data(0, 3), 11_700, 3, readAtSecs = 10_900)
        c.reset()
        assertFalse(c.covers(nowSecs = 11_000, version = 3))
    }
}
