package org.xmtp.android.library.mesh.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.AdvertisingSet
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.AdvertisingSetParameters
import android.os.Build
import android.os.Handler
import android.util.Log
import org.xmtp.android.library.mesh.link.Scheduler
import org.xmtp.android.library.mesh.policy.AdvertSink

/**
 * The platform side of [BleAdvertiser]: starts one advertising set (or legacy advert) and reports
 * its outcome **posted** to the radio thread, never from inside [start]. A seam, so the
 * advertiser's logic runs in plain JVM tests.
 */
internal interface AdvertHost {
    interface Listener {
        /** The start finished with [status] (`ADVERTISE_SUCCESS` or a failure code). */
        fun onStarted(status: Int)

        /** An in-place scan-response update finished with [status]. */
        fun onScanResponseSet(status: Int)
    }

    interface Handle {
        fun stop()

        /** Replaces the running set's scan response; throws [IllegalStateException] if it cannot. */
        fun setScanResponse(serviceData: ByteArray)
    }

    /** Starts advertising [serviceData]; may throw [SecurityException] or [IllegalStateException]. */
    fun start(
        serviceData: ByteArray,
        listener: Listener,
    ): Handle
}

/**
 * Advertises [AdvertPayload]. Each [startNewSet] is a new advertising set (API 26+), which the
 * platform gives a new random address (DESIGN.md §B14.2); older phones restart legacy
 * advertising. [onFailure] reports a permanent inability to advertise; transient failures are
 * retried with the **current** service data from [currentData], never a stale copy. A set that
 * starts after it was replaced or stopped is stopped at once. Radio thread only.
 */
internal class BleAdvertiser(
    private val host: AdvertHost?,
    private val scheduler: Scheduler,
    private val currentData: () -> ByteArray?,
    private val onFailure: (Int) -> Unit = {},
) : AdvertSink {
    private var current: AdvertHost.Handle? = null
    private var started = false

    override fun startNewSet(serviceData: ByteArray) {
        stop()
        if (host == null) {
            Log.w(TAG, "no BLE advertiser available")
            onFailure(STATUS_NO_ADVERTISER)
            return
        }
        var handle: AdvertHost.Handle? = null
        val listener =
            object : AdvertHost.Listener {
                override fun onStarted(status: Int) {
                    val mine = handle ?: return
                    if (current !== mine) {
                        // Replaced or stopped before it started: never leave it on the air.
                        if (status == ADVERTISE_SUCCESS) stopQuietly(mine)
                        return
                    }
                    when (status) {
                        ADVERTISE_SUCCESS -> started = true
                        ADVERTISE_FAILED_ALREADY_STARTED -> Unit
                        ADVERTISE_FAILED_DATA_TOO_LARGE, ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> {
                            Log.w(TAG, "advertising failed: $status")
                            onFailure(status)
                        }
                        else -> {
                            Log.w(TAG, "advertising failed: $status; retrying")
                            scheduler.schedule(RETRY_MS) { if (current === mine) retry() }
                        }
                    }
                }

                override fun onScanResponseSet(status: Int) {
                    val mine = handle ?: return
                    if (current !== mine || status == ADVERTISE_SUCCESS) return
                    Log.w(TAG, "in-place advert update failed: $status; starting a new set")
                    retry()
                }
            }
        try {
            handle = host.start(serviceData, listener)
            current = handle
        } catch (e: SecurityException) {
            Log.w(TAG, "start advertising threw", e)
            onFailure(STATUS_START_EXCEPTION)
        } catch (e: IllegalStateException) {
            Log.w(TAG, "start advertising threw", e)
            onFailure(STATUS_START_EXCEPTION)
        }
    }

    /** Same window, new flags: new data on the running set (same address, same token). */
    override fun updateData(serviceData: ByteArray) {
        val running = current
        if (running != null && started) {
            try {
                running.setScanResponse(serviceData)
                return
            } catch (e: IllegalStateException) {
                Log.w(TAG, "in-place advert update threw; starting a new set", e)
            }
        }
        startNewSet(serviceData)
    }

    override fun stop() {
        current?.let { stopQuietly(it) }
        current = null
        started = false
    }

    private fun retry() {
        currentData()?.let { startNewSet(it) }
    }

    private fun stopQuietly(handle: AdvertHost.Handle) {
        try {
            handle.stop()
        } catch (e: SecurityException) {
            Log.w(TAG, "stop advertising threw", e)
        } catch (e: IllegalStateException) {
            Log.w(TAG, "stop advertising threw", e)
        }
    }

    companion object {
        private const val TAG = "MeshAdvertiser"
        const val RETRY_MS = 30_000L

        // The platform's codes (AdvertiseCallback and AdvertisingSetCallback share them).
        const val ADVERTISE_SUCCESS = 0
        const val ADVERTISE_FAILED_DATA_TOO_LARGE = 1
        const val ADVERTISE_FAILED_ALREADY_STARTED = 3
        const val ADVERTISE_FAILED_FEATURE_UNSUPPORTED = 5

        /** Local-only status codes; no platform failure code is <= 0. */
        const val STATUS_NO_ADVERTISER = -1
        const val STATUS_START_EXCEPTION = -2

        /** The real host, or null when the phone cannot advertise. Callbacks land on [handler]. */
        fun platformHost(
            adapter: BluetoothAdapter,
            handler: Handler,
        ): AdvertHost? {
            if (adapter.bluetoothLeAdvertiser == null) return null
            return if (Build.VERSION.SDK_INT >= 26) SetHost(adapter, handler) else LegacyHost(adapter, handler)
        }
    }
}

/** API 26+: one [AdvertisingSet] per start. */
@SuppressLint("MissingPermission", "NewApi")
private class SetHost(
    private val adapter: BluetoothAdapter,
    private val handler: Handler,
) : AdvertHost {
    override fun start(
        serviceData: ByteArray,
        listener: AdvertHost.Listener,
    ): AdvertHost.Handle {
        var set: AdvertisingSet? = null
        val cb =
            object : AdvertisingSetCallback() {
                override fun onAdvertisingSetStarted(
                    advertisingSet: AdvertisingSet?,
                    txPower: Int,
                    status: Int,
                ) {
                    if (status == BleAdvertiser.ADVERTISE_SUCCESS) set = advertisingSet
                    // Posted: this may run inside startAdvertisingSet on some stacks.
                    handler.post { listener.onStarted(status) }
                }

                override fun onScanResponseDataSet(
                    advertisingSet: AdvertisingSet?,
                    status: Int,
                ) {
                    handler.post { listener.onScanResponseSet(status) }
                }
            }
        val params =
            AdvertisingSetParameters
                .Builder()
                .setLegacyMode(true)
                .setConnectable(true)
                .setScannable(true)
                .setInterval(AdvertisingSetParameters.INTERVAL_MEDIUM)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_MEDIUM)
                .setIncludeTxPower(false)
                .build()
        val advertiser = adapter.bluetoothLeAdvertiser ?: throw IllegalStateException("no BLE advertiser")
        advertiser.startAdvertisingSet(
            params,
            AdvertPayload.advertData(),
            AdvertPayload.scanResponse(serviceData),
            null,
            null,
            cb,
            handler,
        )
        return object : AdvertHost.Handle {
            override fun stop() {
                adapter.bluetoothLeAdvertiser?.stopAdvertisingSet(cb)
            }

            override fun setScanResponse(serviceData: ByteArray) {
                val s = set ?: throw IllegalStateException("advertising set not started")
                s.setScanResponseData(AdvertPayload.scanResponse(serviceData))
            }
        }
    }
}

/** Before API 26: legacy advertising; an update restarts it. */
@SuppressLint("MissingPermission")
private class LegacyHost(
    private val adapter: BluetoothAdapter,
    private val handler: Handler,
) : AdvertHost {
    override fun start(
        serviceData: ByteArray,
        listener: AdvertHost.Listener,
    ): AdvertHost.Handle {
        val settings =
            AdvertiseSettings
                .Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .setConnectable(true)
                .setTimeout(0)
                .build()
        val cb =
            object : AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                    handler.post { listener.onStarted(BleAdvertiser.ADVERTISE_SUCCESS) }
                }

                override fun onStartFailure(errorCode: Int) {
                    handler.post { listener.onStarted(errorCode) }
                }
            }
        val advertiser = adapter.bluetoothLeAdvertiser ?: throw IllegalStateException("no BLE advertiser")
        advertiser.startAdvertising(settings, AdvertPayload.advertData(), AdvertPayload.scanResponse(serviceData), cb)
        return object : AdvertHost.Handle {
            override fun stop() {
                adapter.bluetoothLeAdvertiser?.stopAdvertising(cb)
            }

            override fun setScanResponse(serviceData: ByteArray): Unit =
                throw IllegalStateException("legacy advertising has no in-place update")
        }
    }
}
