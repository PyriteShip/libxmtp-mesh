package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * While stopped there is no node: reads are null, actions throw MeshException(NOT_RUNNING),
 * and pairing mode cannot be left on (DESIGN.md §B14.4). Only the stopped path runs here; it
 * never calls native code.
 */
class MeshApiStoppedTest {
    @Test
    fun pairingStateIsNullWhileStopped() {
        Mesh.setPairingMode(true)
        assertNull(Mesh.pairingState())
    }

    @Test
    fun readsAreNullWhileStopped() {
        assertNull(Mesh.contacts())
        assertNull(Mesh.restoreWindowUntil())
    }

    @Test
    fun actionsThrowWhileStopped() {
        for (action in listOf<() -> Unit>(
            { Mesh.confirmPairing("p#1") },
            { Mesh.rejectPairing("p#1") },
            { Mesh.removeContact("bob") },
            { Mesh.forgetContact("bob") },
            { Mesh.resetDiscoveryKey() },
            { Mesh.endRestoreWindow() },
            { Mesh.confirmRestoredContact("bob") },
        )) {
            val e = assertThrows(MeshException::class.java) { action() }
            assertEquals(Mesh.NOT_RUNNING, e.message)
        }
    }
}
