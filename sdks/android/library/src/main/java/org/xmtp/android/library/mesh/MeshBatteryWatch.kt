package org.xmtp.android.library.mesh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build

/**
 * Follows ACTION_BATTERY_CHANGED (sticky) while the radio runs and reports
 * (percent, charging); percent is -1 when unknown. [readNow] returns the sticky value at once,
 * so Mesh.start can decide before the radio links come up.
 */
internal class MeshBatteryWatch(
    private val context: Context,
    private val onChange: (percent: Int, charging: Boolean) -> Unit,
) {
    private val receiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                c: Context,
                intent: Intent,
            ) {
                val (p, ch) = parse(intent)
                onChange(p, ch)
            }
        }

    fun readNow(): Pair<Int, Boolean> =
        context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))?.let(::parse) ?: (-1 to false)

    fun start() {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
    }

    fun stop() {
        try {
            context.unregisterReceiver(receiver)
        } catch (_: IllegalArgumentException) {
            // not registered
        }
    }

    private fun parse(intent: Intent): Pair<Int, Boolean> {
        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val percent = if (level >= 0 && scale > 0) level * 100 / scale else -1
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        return percent to charging
    }
}
