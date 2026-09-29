package org.xmtp.android.library.mesh

import android.os.ParcelUuid
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.xmtp.android.library.mesh.ble.AdvertPayload
import org.xmtp.android.library.mesh.ble.BleConstants

/** Nothing in the advert names the phone: no device name, no TX power, no manufacturer data (DESIGN.md §B14.2). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class AdvertPayloadTest {
    private val uuid = ParcelUuid(BleConstants.SERVICE_UUID)

    @Test
    fun theAdvertCarriesOnlyTheServiceUuid() {
        val d = AdvertPayload.advertData()
        assertFalse(d.includeDeviceName)
        assertFalse(d.includeTxPowerLevel)
        assertEquals(0, d.manufacturerSpecificData.size())
        assertEquals(listOf(uuid), d.serviceUuids)
        assertEquals(0, d.serviceData.size)
    }

    @Test
    fun theScanResponseCarriesExactlyTheNodesServiceData() {
        val sd = byteArrayOf(2, 0) + ByteArray(8) { 7 }
        val r = AdvertPayload.scanResponse(sd)
        assertFalse(r.includeDeviceName)
        assertFalse(r.includeTxPowerLevel)
        assertEquals(0, r.manufacturerSpecificData.size())
        assertEquals(setOf(uuid), r.serviceData.keys)
        assertArrayEquals(sd, r.serviceData[uuid])
        assertEquals(null, r.serviceUuids?.takeIf { it.isNotEmpty() })
    }
}
