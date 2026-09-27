package org.xmtp.android.library.mesh.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Handler
import android.util.Log
import org.xmtp.android.library.mesh.policy.InboundSubscriptions
import org.xmtp.android.library.mesh.policy.PeerTable

/**
 * Our inbound (peripheral) side. A central becomes a link only when it
 * subscribes to TX. Android also reports our own outbound connections to this
 * callback; those never subscribe, so they never become links here.
 *
 * [onServiceReady] runs on the radio thread once the platform has added (true)
 * or failed to add (false) the mesh service; advertise only after true.
 */
@SuppressLint("MissingPermission")
internal class GattServerHost(
    private val context: Context,
    private val manager: BluetoothManager,
    private val handler: Handler,
    private val events: ConnectionEvents,
    private val onServiceReady: (Boolean) -> Unit = {},
) {
    @Volatile private var server: BluetoothGattServer? = null
    private var tx: BluetoothGattCharacteristic? = null
    private val devices = HashMap<String, BluetoothDevice>()
    private val mtus = HashMap<String, Int>()
    private val subscriptions = InboundSubscriptions()

    private fun key(device: BluetoothDevice) = "s:${device.address}"

    private val callback =
        object : BluetoothGattServerCallback() {
            override fun onServiceAdded(
                status: Int,
                service: BluetoothGattService,
            ) {
                if (service.uuid != BleConstants.SERVICE_UUID) return
                handler.post { onServiceReady(status == BluetoothGatt.GATT_SUCCESS) }
            }

            override fun onConnectionStateChange(
                device: BluetoothDevice,
                status: Int,
                newState: Int,
            ) {
                handler.post {
                    val k = key(device)
                    if (newState == BluetoothProfile.STATE_CONNECTED) {
                        devices[k] = device
                    } else {
                        devices.remove(k)
                        mtus.remove(k)
                        if (subscriptions.disconnected(k)) events.onGattClosed(k, status)
                    }
                }
            }

            override fun onMtuChanged(
                device: BluetoothDevice,
                mtu: Int,
            ) {
                handler.post { mtus[key(device)] = mtu }
            }

            override fun onDescriptorWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                descriptor: BluetoothGattDescriptor,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?,
            ) {
                if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                if (descriptor.uuid != BleConstants.CCCD_UUID || value == null) return
                val enable = value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                val disable = value.contentEquals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)
                if (!enable && !disable) return
                handler.post {
                    val k = key(device)
                    if (enable) {
                        if (subscriptions.enable(k)) {
                            devices[k] = device
                            events.onGattReady(k, PeerTable.Role.PERIPHERAL, mtus[k] ?: BleConstants.DEFAULT_MTU)
                        }
                    } else if (subscriptions.disable(k)) {
                        events.onGattClosed(k, BluetoothGatt.GATT_SUCCESS)
                    }
                }
            }

            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?,
            ) {
                if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                if (characteristic.uuid != BleConstants.RX_UUID || value == null) return
                val copy = value.copyOf()
                val k = key(device)
                // Only a subscribed central is a link; an unsubscribed write (or one that
                // raced an unsubscribe) is not delivered.
                handler.post { if (subscriptions.contains(k)) events.onGattPacket(k, copy) }
            }

            override fun onNotificationSent(
                device: BluetoothDevice,
                status: Int,
            ) {
                handler.post { events.onGattWriteComplete(key(device)) }
            }
        }

    /** Idempotent: closes any previously open server first. */
    fun open(): Boolean {
        close()
        val s =
            try {
                manager.openGattServer(context, callback)
            } catch (e: SecurityException) {
                Log.w(TAG, "openGattServer threw", e)
                null
            } catch (e: IllegalStateException) {
                Log.w(TAG, "openGattServer threw", e)
                null
            } ?: return false
        val service = BluetoothGattService(BleConstants.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val rx =
            BluetoothGattCharacteristic(
                BleConstants.RX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            )
        val notify =
            BluetoothGattCharacteristic(
                BleConstants.TX_UUID,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ,
            )
        notify.addDescriptor(
            BluetoothGattDescriptor(
                BleConstants.CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
            ),
        )
        service.addCharacteristic(rx)
        service.addCharacteristic(notify)
        val added =
            try {
                s.addService(service)
            } catch (e: SecurityException) {
                Log.w(TAG, "addService threw", e)
                false
            } catch (e: IllegalStateException) {
                Log.w(TAG, "addService threw", e)
                false
            }
        if (!added) {
            s.close()
            return false
        }
        server = s
        tx = notify
        return true
    }

    fun notify(
        key: String,
        packet: ByteArray,
    ): Boolean {
        val s = server ?: return false
        val characteristic = tx ?: return false
        val device = devices[key] ?: return false
        if (!subscriptions.contains(key)) return false
        return try {
            BleCompat.notify(s, device, characteristic, packet)
        } catch (e: SecurityException) {
            Log.w(TAG, "notify threw", e)
            false
        } catch (e: IllegalStateException) {
            Log.w(TAG, "notify threw", e)
            false
        }
    }

    /**
     * Drops the whole LE connection to that device. Use only for peers we
     * refuse (over budget, failed mesh auth). For duplicate links, send BYE
     * instead; the remote central closes its side.
     */
    fun disconnect(key: String) {
        devices[key]?.let { server?.cancelConnection(it) }
    }

    /**
     * The radio closed this inbound link without dropping the LE connection. Forget the
     * subscription so the central can re-subscribe as a new link.
     */
    fun forget(key: String) {
        subscriptions.forget(key)
    }

    fun close() {
        server?.close()
        server = null
        devices.clear()
        mtus.clear()
        subscriptions.clear()
    }

    private companion object {
        const val TAG = "MeshGattServer"
    }
}
