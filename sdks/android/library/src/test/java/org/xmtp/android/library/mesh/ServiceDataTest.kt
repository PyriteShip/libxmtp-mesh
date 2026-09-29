package org.xmtp.android.library.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.ServiceData

/** Service data `2 ‖ flags ‖ token(8)` (DESIGN.md §B14.2). */
class ServiceDataTest {
    private fun v2(
        flags: Int,
        token: ByteArray = ByteArray(8) { it.toByte() },
    ) = byteArrayOf(2, flags.toByte()) + token

    @Test
    fun v2ServiceDataIsRecognised() {
        assertTrue(ServiceData.isV2(v2(0)))
    }

    /** A mesh.10 phone advertises version 1 with a short id: never dialed, so no reconnect loop. */
    @Test
    fun olderBuildsAndJunkAreNot() {
        assertFalse(ServiceData.isV2(byteArrayOf(1, 0) + ByteArray(8)))
        assertFalse(ServiceData.isV2(v2(0).copyOf(9)))
        assertFalse(ServiceData.isV2(v2(0) + byteArrayOf(0)))
        assertFalse(ServiceData.isV2(null))
        assertFalse(ServiceData.isV2(ByteArray(0)))
    }

    @Test
    fun flagsAndToken() {
        val d = v2(ServiceData.FLAG_PAIRING or ServiceData.FLAG_RELAY)
        assertTrue(ServiceData.pairing(d))
        assertTrue(ServiceData.relayOffered(d))
        assertFalse(ServiceData.pairing(v2(ServiceData.FLAG_RELAY)))
        assertArrayEquals(ByteArray(8) { it.toByte() }, ServiceData.token(d))
        assertEquals("00010203", ServiceData.hexPrefix(ServiceData.token(d)))
    }
}
