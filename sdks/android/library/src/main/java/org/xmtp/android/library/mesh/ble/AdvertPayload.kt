package org.xmtp.android.library.mesh.ble

import android.bluetooth.le.AdvertiseData
import android.os.ParcelUuid

/**
 * What the phone puts on the air (DESIGN.md §B14.2): the service UUID in the advert (flags +
 * UUID = 21 of 31 bytes) and exactly the node's service data in the scan response (28 of 31
 * bytes). No device name, no TX power, no manufacturer data. The UUID only says "a PyriteChat
 * phone"; the service data's token changes every window.
 */
internal object AdvertPayload {
    private val uuid = ParcelUuid(BleConstants.SERVICE_UUID)

    fun advertData(): AdvertiseData =
        AdvertiseData
            .Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(uuid)
            .build()

    fun scanResponse(serviceData: ByteArray): AdvertiseData =
        AdvertiseData
            .Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceData(uuid, serviceData)
            .build()
}
