package org.xmtp.android.library.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.MeshAdvertisement

class AdvertisementTest {
    private val id = ByteArray(8) { (0x10 + it).toByte() }

    @Test
    fun round_trips_with_pairing_flag() {
        val bytes = MeshAdvertisement(1, MeshAdvertisement.FLAG_PAIRING, id).encode()
        assertEquals(10, bytes.size)
        val ad = MeshAdvertisement.decode(bytes)!!
        assertTrue(ad.pairingMode)
        assertArrayEquals(id, ad.shortId)
        assertFalse(MeshAdvertisement.decode(MeshAdvertisement(1, 0, id).encode())!!.pairingMode)
    }

    @Test
    fun unknown_version_short_or_missing_data_is_ignored() {
        assertNull(MeshAdvertisement.decode(null))
        assertNull(MeshAdvertisement.decode(ByteArray(9)))
        assertNull(MeshAdvertisement.decode(byteArrayOf(2, 0) + id))
    }

    @Test
    fun trailing_bytes_are_tolerated() {
        assertArrayEquals(id, MeshAdvertisement.decode(MeshAdvertisement(1, 0, id).encode() + byteArrayOf(9))!!.shortId)
    }

    @Test
    fun service_data_fits_legacy_scan_response() {
        // AD structure: len(1) + type(1) + 128-bit UUID(16) + payload must be <= 31
        assertTrue(2 + 16 + MeshAdvertisement.SIZE <= 31)
    }
}
