package org.xmtp.android.library.mesh.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import android.os.Handler
import android.util.Log
import org.xmtp.android.library.mesh.policy.PeerTable

/**
 * Our outbound (central) side of one link: connect → MTU 517 → discover →
 * subscribe to TX → ready. Any failure (including GATT 133) closes the
 * BluetoothGatt fully and reports [ConnectionEvents.onGattClosed]; the radio
 * owns retry/backoff.
 */
@SuppressLint("MissingPermission")
internal class GattClientConnection(
    private val context: Context,
    private val device: BluetoothDevice,
    private val handler: Handler,
    private val events: ConnectionEvents,
) {
    val key: String = "c:${device.address}"
    private var gatt: BluetoothGatt? = null
    private var rx: BluetoothGattCharacteristic? = null
    private var mtu = BleConstants.DEFAULT_MTU
    private var ready = false
    private var closed = false
    private val connectTimeout = Runnable { fail(BleConstants.STATUS_LOCAL_TIMEOUT) }

    private val callback =
        object : BluetoothGattCallback() {
            override fun onConnectionStateChange(
                g: BluetoothGatt,
                status: Int,
                newState: Int,
            ) {
                handler.post {
                    if (closed) return@post
                    if (status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) {
                        if (!g.requestMtu(BleConstants.REQUESTED_MTU)) g.discoverServices()
                    } else {
                        fail(status)
                    }
                }
            }

            override fun onMtuChanged(
                g: BluetoothGatt,
                newMtu: Int,
                status: Int,
            ) {
                handler.post {
                    if (closed) return@post
                    if (status == BluetoothGatt.GATT_SUCCESS) mtu = newMtu
                    // A ready link can still get a later MTU renegotiation. Do not re-run
                    // discovery on it: that can fail(STATUS_NO_SERVICE) a healthy link or
                    // swap `rx` out from under an in-flight write.
                    if (ready) return@post
                    g.discoverServices()
                }
            }

            override fun onServicesDiscovered(
                g: BluetoothGatt,
                status: Int,
            ) {
                handler.post {
                    if (closed || ready) return@post
                    val service = g.getService(BleConstants.SERVICE_UUID)
                    rx = service?.getCharacteristic(BleConstants.RX_UUID)
                    val tx = service?.getCharacteristic(BleConstants.TX_UUID)
                    when {
                        status != BluetoothGatt.GATT_SUCCESS -> fail(status)
                        rx == null || tx == null -> fail(BleConstants.STATUS_NO_SERVICE)
                        !BleCompat.enableNotifications(g, tx) -> fail(BleConstants.STATUS_NO_SERVICE)
                    }
                }
            }

            override fun onDescriptorWrite(
                g: BluetoothGatt,
                descriptor: BluetoothGattDescriptor,
                status: Int,
            ) {
                handler.post {
                    if (closed || ready) return@post
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        fail(status)
                        return@post
                    }
                    ready = true
                    handler.removeCallbacks(connectTimeout)
                    events.onGattReady(key, PeerTable.Role.CENTRAL, mtu)
                }
            }

            @Deprecated("Used below API 33")
            @Suppress("DEPRECATION")
            override fun onCharacteristicChanged(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
            ) {
                val value = characteristic.value?.copyOf() ?: return
                handler.post { if (!closed) events.onGattPacket(key, value) }
            }

            override fun onCharacteristicChanged(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
            ) {
                val copy = value.copyOf()
                handler.post { if (!closed) events.onGattPacket(key, copy) }
            }

            override fun onCharacteristicWrite(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                handler.post { if (!closed) events.onGattWriteComplete(key) }
            }

            @SuppressLint("InlinedApi")
            // PHY_LE_CODED (API 26) is a compile-time int constant; reading it is safe on
            // minSdk 23 too, and this callback only ever fires after an API>=26 PHY request.
            override fun onPhyUpdate(
                g: BluetoothGatt,
                txPhy: Int,
                rxPhy: Int,
                status: Int,
            ) {
                handler.post {
                    if (!closed) {
                        events.onGattPhyUpdate(
                            key,
                            txPhy == BluetoothDevice.PHY_LE_CODED,
                            rxPhy == BluetoothDevice.PHY_LE_CODED,
                            status == BluetoothGatt.GATT_SUCCESS,
                        )
                    }
                }
            }
        }

    fun connect() {
        if (closed) return
        gatt =
            try {
                if (Build.VERSION.SDK_INT >= 26) {
                    device.connectGatt(
                        context,
                        false,
                        callback,
                        BluetoothDevice.TRANSPORT_LE,
                        BluetoothDevice.PHY_LE_1M_MASK,
                        handler,
                    )
                } else {
                    device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
                }
            } catch (e: SecurityException) {
                Log.w(TAG, "connectGatt threw", e)
                null
            } catch (e: IllegalStateException) {
                Log.w(TAG, "connectGatt threw", e)
                null
            }
        if (gatt == null) {
            handler.post { fail(BleConstants.STATUS_NO_GATT) }
            return
        }
        handler.postDelayed(connectTimeout, BleConstants.CONNECT_TIMEOUT_MS)
    }

    fun write(packet: ByteArray): Boolean {
        val g = gatt ?: return false
        val characteristic = rx ?: return false
        return BleCompat.writeNoResponse(g, characteristic, packet)
    }

    fun requestCodedPhy() {
        if (Build.VERSION.SDK_INT >= 26) {
            gatt?.setPreferredPhy(
                BluetoothDevice.PHY_LE_CODED_MASK,
                BluetoothDevice.PHY_LE_CODED_MASK,
                BluetoothDevice.PHY_OPTION_S8,
            )
        }
    }

    fun request1mPhy() {
        if (Build.VERSION.SDK_INT >= 26) {
            gatt?.setPreferredPhy(
                BluetoothDevice.PHY_LE_1M_MASK,
                BluetoothDevice.PHY_LE_1M_MASK,
                BluetoothDevice.PHY_OPTION_NO_PREFERRED,
            )
        }
    }

    /** Close without reporting (the caller already knows). */
    fun close() {
        if (closed) return
        closed = true
        handler.removeCallbacks(connectTimeout)
        gatt?.let {
            it.disconnect()
            it.close()
        }
        gatt = null
    }

    private fun fail(status: Int) {
        if (closed) return
        close()
        events.onGattClosed(key, status)
    }

    private companion object {
        const val TAG = "MeshGattClient"
    }
}
