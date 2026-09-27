package org.xmtp.android.library.mesh

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log

/**
 * Keeps the process alive for background BLE (DESIGN.md §B7). The radio itself is
 * owned by [Mesh]; this service only holds the foreground state and notification.
 */
class MeshForegroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        // Always go foreground first, even to stop: a service started with
        // startForegroundService that stops without calling startForeground crashes the app.
        val foreground = goForeground()
        MeshForeground.onStartResult(foreground)
        // stopSelfResult(startId), not stopSelf(): in a fast STOP → START pair (Mesh.stop, then
        // Mesh.start for the next client) a bare stopSelf() would also drop the newer start,
        // leaving the radio up with no foreground service.
        if (!foreground) {
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        if (MeshServiceCommand.of(intent?.action) == MeshServiceCommand.STOP) {
            leaveForeground()
            MeshForeground.onStopped()
            stopSelfResult(startId)
        }
        // Not sticky: after a process kill the app must call Mesh.start again (it needs a Client).
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        MeshForeground.onStopped()
        super.onDestroy()
    }

    private fun goForeground(): Boolean {
        val notification = buildNotification()
        return try {
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            true
        } catch (e: IllegalStateException) {
            // ForegroundServiceStartNotAllowedException (API 31+) and the API 34
            // foreground-service-type exceptions are IllegalStateExceptions.
            Log.w(TAG, "startForeground refused", e)
            false
        } catch (e: SecurityException) {
            // API 34+: FOREGROUND_SERVICE_CONNECTED_DEVICE needs a granted Bluetooth permission.
            Log.w(TAG, "startForeground refused", e)
            false
        }
    }

    private fun leaveForeground() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun buildNotification(): Notification {
        val builder =
            if (Build.VERSION.SDK_INT >= 26) {
                getSystemService(NotificationManager::class.java).createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Nearby messaging", NotificationManager.IMPORTANCE_LOW),
                )
                Notification.Builder(this, CHANNEL_ID)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(this)
            }
        return builder
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle("Messaging nearby")
            .setContentText("Keeping Bluetooth connections to nearby contacts")
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "MeshForegroundService"
        private const val CHANNEL_ID = "xmtp_mesh"
        private const val NOTIFICATION_ID = 0x6d657368

        fun start(context: Context) {
            send(context, Intent(context, MeshForegroundService::class.java))
        }

        /**
         * Delivered as a start command rather than stopService, so a stop that races
         * a pending start still lets the service call startForeground first.
         */
        fun stop(context: Context) {
            val intent = Intent(context, MeshForegroundService::class.java).setAction(MeshServiceCommand.ACTION_STOP)
            try {
                send(context, intent)
            } catch (e: IllegalStateException) {
                // Not allowed to start a service from the background (API 26+/31+). A service
                // that is already foreground is then stopped directly; there is no pending start
                // to race, since that start would have been refused the same way.
                Log.w(TAG, "stop command refused; stopping directly", e)
                stopDirectly(context)
            }
        }

        // Lint's ImplicitSamInstance misfires here: stopService matches the service by component, not instance.
        @SuppressLint("ImplicitSamInstance")
        private fun stopDirectly(context: Context) {
            context.stopService(Intent(context, MeshForegroundService::class.java))
        }

        private fun send(
            context: Context,
            intent: Intent,
        ) {
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }
    }
}
