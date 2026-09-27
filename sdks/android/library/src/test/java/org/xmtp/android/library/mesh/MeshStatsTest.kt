package org.xmtp.android.library.mesh

import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Mesh.stats() reads the running node; while stopped there is no node, so it is null
 * (DESIGN.md §B13 counters). The FFI node can't open in a JVM test; this only
 * touches the stopped path, which never calls into native code.
 */
class MeshStatsTest {
    @Test
    fun statsAreNullWhileTheMeshIsStopped() {
        assertNull(Mesh.stats())
    }
}
