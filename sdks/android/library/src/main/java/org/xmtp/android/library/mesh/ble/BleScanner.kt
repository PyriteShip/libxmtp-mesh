package org.xmtp.android.library.mesh.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.os.Handler
import android.os.ParcelUuid
import android.util.Log
import org.xmtp.android.library.mesh.link.Cancellable
import org.xmtp.android.library.mesh.link.Scheduler
import org.xmtp.android.library.mesh.policy.ScanSchedule
import org.xmtp.android.library.mesh.policy.ScanStartLimiter
import org.xmtp.android.library.mesh.policy.ServiceData

/**
 * Duty-cycled, filtered scan (filtered scans keep running with the screen off).
 * Active scanning is Android's default, which is what delivers the scan response
 * carrying the service data **(verify on device)**.
 */
@SuppressLint("MissingPermission")
internal class BleScanner(
    private val adapter: BluetoothAdapter,
    private val handler: Handler,
    private val scheduler: Scheduler,
    private val schedule: ScanSchedule,
    private val onSighting: (ByteArray, BluetoothDevice, Int) -> Unit,
    private val nearbyState: () -> Pair<Long?, Int>,
    /** Shared across scanner instances by the radio, so restarts count too. */
    private val startLimiter: ScanStartLimiter = ScanStartLimiter(),
) {
    private var running = false
    private var scanning = false
    private var timer: Cancellable? = null
    private val uuid = ParcelUuid(BleConstants.SERVICE_UUID)
    private val filters = listOf(ScanFilter.Builder().setServiceUuid(uuid).build())
    private val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()

    private val callback =
        object : ScanCallback() {
            override fun onScanResult(
                callbackType: Int,
                result: ScanResult,
            ) {
                val data = result.scanRecord?.getServiceData(uuid) ?: return
                if (!ServiceData.isV2(data)) return
                val device = result.device
                val rssi = result.rssi
                handler.post { if (running) onSighting(data, device, rssi) }
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                results.forEach { onScanResult(ScanSettings.CALLBACK_TYPE_ALL_MATCHES, it) }
            }

            override fun onScanFailed(errorCode: Int) {
                // Not guaranteed to run on the radio handler; hop over before touching
                // `scanning`, which only the radio thread otherwise reads/writes.
                handler.post {
                    Log.w(TAG, "scan failed: $errorCode")
                    // ALREADY_STARTED means a scan is in fact running (e.g. a stray
                    // startScan raced a prior one); anything else means it is not.
                    scanning = errorCode == SCAN_FAILED_ALREADY_STARTED
                }
            }
        }

    fun start() {
        if (running) return
        running = true
        cycleOn()
    }

    fun stop() {
        running = false
        timer?.cancel()
        timer = null
        stopScan()
    }

    private fun cycleOn() {
        if (!running) return
        val wait = startLimiter.delayMs(scheduler.nowMs())
        if (wait > 0) {
            Log.i(TAG, "scan start deferred ${wait}ms (Android allows 5 starts per 30 s)")
            timer = scheduler.schedule(wait) { cycleOn() }
            return
        }
        val (lastSighting, connected) = nearbyState()
        val window = schedule.window(scheduler.nowMs(), lastSighting, connected)
        startScan()
        timer =
            scheduler.schedule(window.onMs) {
                stopScan()
                timer = scheduler.schedule(window.offMs) { cycleOn() }
            }
    }

    private fun startScan() {
        if (scanning) return
        val scanner = adapter.bluetoothLeScanner ?: return
        try {
            startLimiter.record(scheduler.nowMs())
            scanner.startScan(filters, settings, callback)
            scanning = true
        } catch (e: SecurityException) {
            Log.w(TAG, "startScan threw", e)
            scanning = false
        } catch (e: IllegalStateException) {
            Log.w(TAG, "startScan threw", e)
            scanning = false
        }
    }

    /** Idempotent: always asks the platform to stop, even if our own state thinks it is already off. */
    private fun stopScan() {
        scanning = false
        try {
            adapter.bluetoothLeScanner?.stopScan(callback)
        } catch (e: SecurityException) {
            Log.w(TAG, "stopScan threw", e)
        } catch (e: IllegalStateException) {
            Log.w(TAG, "stopScan threw", e)
        }
    }

    private companion object {
        const val TAG = "MeshScanner"
    }
}
