package org.xmtp.android.library.mesh.ble

import android.annotation.SuppressLint
import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.SystemClock
import java.util.UUID

/**
 * Wakes the radio at the next advert window even in Doze (DESIGN.md §B14.2). Inexact
 * (`setAndAllowWhileIdle`, no exact-alarm permission): the radio's own tick and every BLE
 * event also check the clock, so this is the backstop, not the only trigger.
 *
 * **Lateness.** In Doze the platform rate-limits while-idle alarms (several minutes apart), so
 * a phone can keep the previous window's token and address for some minutes after a boundary.
 * Contacts match tokens for windows `w-1 ..= w+1`, which absorbs up to one window of lateness.
 *
 * [onAlarm] receives a `done` callback and must call it once its work has finished: the
 * receiver holds a [BroadcastReceiver.goAsync] result until then, so the device stays awake
 * for the check. Alarms closer together than [MIN_GAP_MS] are ignored.
 */
internal class WindowAlarm(
    private val context: Context,
    private val onAlarm: (done: () -> Unit) -> Unit,
) {
    // A per-process random suffix: before API 33 the receiver is exported, and another app
    // cannot send an action it cannot guess.
    private val action = "${context.packageName}.xmtp.mesh.ADVERT_WINDOW.$PROCESS_SUFFIX"
    private val manager = context.getSystemService(AlarmManager::class.java)
    private val intent =
        PendingIntent.getBroadcast(
            context,
            0,
            Intent(action).setPackage(context.packageName),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    private val receiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                c: Context,
                i: Intent,
            ) {
                val now = SystemClock.elapsedRealtime()
                val last = lastFiredMs
                if (last != null && now - last < MIN_GAP_MS) return
                lastFiredMs = now
                val pending = goAsync()
                onAlarm { pending.finish() }
            }
        }
    private var registered = false
    private var lastFiredMs: Long? = null // main thread only (onReceive)

    fun arm(delayMs: Long) {
        if (!registered) {
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(receiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerBeforeApi33()
            }
            registered = true
        }
        manager?.setAndAllowWhileIdle(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + delayMs,
            intent,
        )
    }

    /**
     * Before API 33 a runtime receiver cannot be marked not-exported. The action carries a
     * per-process random suffix, and a spoofed broadcast would only cause an early clock check,
     * which does nothing until a window is due.
     */
    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun registerBeforeApi33() {
        context.registerReceiver(receiver, IntentFilter(action))
    }

    fun disarm() {
        manager?.cancel(intent)
        if (registered) runCatching { context.unregisterReceiver(receiver) }
        registered = false
    }

    companion object {
        const val MIN_GAP_MS = 10_000L
        private val PROCESS_SUFFIX = UUID.randomUUID().toString()
    }
}
