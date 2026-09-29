package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.PeerTable

/** Every connection gets a fresh PeerId (xmtp_mesh MeshTransport contract); the node resolves duplicates. */
class PeerTableTest {
    @Test
    fun everyLinkGetsItsOwnPeerId() {
        val t = PeerTable()
        val a = t.onLinkReady("c:AA")
        val b = t.onLinkReady("s:BB")
        assertNotEquals(a, b)
        assertTrue(a.startsWith("p#") && b.startsWith("p#"))
        assertEquals(setOf(a, b), t.peers())
        assertEquals("c:AA", t.keyForPeerId(a))
        assertEquals(a, t.peerIdOf("c:AA"))
    }

    @Test
    fun aNewLinkOnTheSameKeyAfterACloseGetsANewPeerId() {
        val t = PeerTable()
        val first = t.onLinkReady("c:AA")
        assertEquals(first, t.onLinkClosed("c:AA"))
        assertNull(t.keyForPeerId(first))
        assertNull(t.onLinkClosed("c:AA"))
        assertNotEquals(first, t.onLinkReady("c:AA"))
    }
}
