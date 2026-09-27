package org.xmtp.android.library.mesh

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A refused startForeground used to be invisible to the host. */
class MeshForegroundTest {
    @After
    fun reset() = MeshForeground.onStopped()

    @Test
    fun starts_not_foreground() {
        assertFalse(MeshForeground.active.value)
    }

    @Test
    fun a_granted_start_is_foreground_and_a_refused_one_is_not() {
        MeshForeground.onStartResult(true)
        assertTrue(MeshForeground.active.value)
        MeshForeground.onStartResult(false)
        assertFalse(MeshForeground.active.value)
    }

    @Test
    fun stopping_clears_it() {
        MeshForeground.onStartResult(true)
        MeshForeground.onStopped()
        assertFalse(MeshForeground.active.value)
    }
}
