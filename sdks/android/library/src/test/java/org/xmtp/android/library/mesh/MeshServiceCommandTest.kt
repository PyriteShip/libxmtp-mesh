package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test

class MeshServiceCommandTest {
    @Test
    fun stop_action_stops_after_going_foreground() {
        assertEquals(MeshServiceCommand.STOP, MeshServiceCommand.of(MeshServiceCommand.ACTION_STOP))
    }

    @Test
    fun anything_else_keeps_running() {
        assertEquals(MeshServiceCommand.RUN, MeshServiceCommand.of(null))
        assertEquals(MeshServiceCommand.RUN, MeshServiceCommand.of("android.intent.action.MAIN"))
    }
}
