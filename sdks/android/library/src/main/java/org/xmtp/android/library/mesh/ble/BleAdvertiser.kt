package org.xmtp.android.library.mesh.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.os.Handler
import android.os.ParcelUuid
import android.util.Log
import org.xmtp.android.library.mesh.policy.MeshAdvertisement

/**
 * Advertising data: the 128-bit service UUID (flags + UUID = 21 of 31 bytes).
 * Scan response: service data = [MeshAdvertisement] (28 of 31 bytes).
 *
 * [onFailure] reports a permanent inability to advertise: no advertiser available
 * (multi-advertisement unsupported), a permanent platform failure code
 * (`ADVERTISE_FAILED_FEATURE_UNSUPPORTED`, `ADVERTISE_FAILED_DATA_TOO_LARGE`), or a
 * platform throw from `startAdvertising`. Transient failures are retried internally
 * and never reach [onFailure].
 */
@SuppressLint("MissingPermission")
internal class BleAdvertiser(
    private val adapter: BluetoothAdapter,
    private val handler: Handler,
    private val onFailure: (Int) -> Unit = {},
) {
    private var callback: AdvertiseCallback? = null

    fun start(ad: MeshAdvertisement) {
        stop()
        val advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.w(TAG, "no BLE advertiser available")
            onFailure(STATUS_NO_ADVERTISER)
            return
        }
        val settings =
            AdvertiseSettings
                .Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .setConnectable(true)
                .setTimeout(0)
                .build()
        val uuid = ParcelUuid(BleConstants.SERVICE_UUID)
        val data =
            AdvertiseData
                .Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(uuid)
                .build()
        val scanResponse =
            AdvertiseData
                .Builder()
                .setIncludeDeviceName(false)
                .addServiceData(uuid, ad.encode())
                .build()
        val cb =
            object : AdvertiseCallback() {
                override fun onStartFailure(errorCode: Int) {
                    Log.w(TAG, "advertising failed: $errorCode")
                    when (errorCode) {
                        ADVERTISE_FAILED_ALREADY_STARTED -> Unit
                        ADVERTISE_FAILED_FEATURE_UNSUPPORTED, ADVERTISE_FAILED_DATA_TOO_LARGE -> onFailure(errorCode)
                        else -> handler.postDelayed({ if (callback === this) start(ad) }, RETRY_MS)
                    }
                }
            }
        callback = cb
        try {
            advertiser.startAdvertising(settings, data, scanResponse, cb)
        } catch (e: SecurityException) {
            Log.w(TAG, "startAdvertising threw", e)
            callback = null
            onFailure(STATUS_START_EXCEPTION)
        } catch (e: IllegalStateException) {
            Log.w(TAG, "startAdvertising threw", e)
            callback = null
            onFailure(STATUS_START_EXCEPTION)
        }
    }

    fun stop() {
        callback?.let {
            try {
                adapter.bluetoothLeAdvertiser?.stopAdvertising(it)
            } catch (e: SecurityException) {
                Log.w(TAG, "stopAdvertising threw", e)
            } catch (e: IllegalStateException) {
                Log.w(TAG, "stopAdvertising threw", e)
            }
        }
        callback = null
    }

    private companion object {
        const val TAG = "MeshAdvertiser"
        const val RETRY_MS = 30_000L

        /** Local-only status codes; no `AdvertiseCallback.ADVERTISE_FAILED_*` value is <= 0. */
        const val STATUS_NO_ADVERTISER = -1
        const val STATUS_START_EXCEPTION = -2
    }
}
