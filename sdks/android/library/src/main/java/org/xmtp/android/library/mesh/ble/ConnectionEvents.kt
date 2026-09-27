package org.xmtp.android.library.mesh.ble

import org.xmtp.android.library.mesh.policy.PeerTable

/** Called on the radio thread. [key] identifies one GATT connection ("c:" outbound, "s:" inbound). */
internal interface ConnectionEvents {
    fun onGattReady(
        key: String,
        role: PeerTable.Role,
        mtu: Int,
    )

    fun onGattPacket(
        key: String,
        packet: ByteArray,
    )

    fun onGattWriteComplete(key: String)

    fun onGattPhyUpdate(
        key: String,
        txCoded: Boolean,
        rxCoded: Boolean,
        ok: Boolean,
    )

    fun onGattClosed(
        key: String,
        status: Int,
    )
}
