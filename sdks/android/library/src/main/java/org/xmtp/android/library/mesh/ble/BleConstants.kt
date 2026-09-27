package org.xmtp.android.library.mesh.ble

import java.util.UUID

object BleConstants {
    /** "xmtpmesh" in ASCII, then a service number. Advertised; scanned for. */
    val SERVICE_UUID: UUID = UUID.fromString("786d7470-6d65-7368-0000-000000000001")

    /** Central writes link packets here (write without response). */
    val RX_UUID: UUID = UUID.fromString("786d7470-6d65-7368-0000-000000000002")

    /** Peripheral notifies link packets here. */
    val TX_UUID: UUID = UUID.fromString("786d7470-6d65-7368-0000-000000000003")
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    const val REQUESTED_MTU = 517
    const val DEFAULT_MTU = 23
    const val CONNECT_TIMEOUT_MS = 10_000L

    const val STATUS_LOCAL_TIMEOUT = -1
    const val STATUS_NO_GATT = -2
    const val STATUS_NO_SERVICE = -3
}
