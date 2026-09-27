package org.xmtp.android.library.mesh

/**
 * What [MeshForegroundService] does with a start intent. Every start goes
 * foreground first (a service started with startForegroundService must call
 * startForeground, even one that is about to stop); STOP then leaves.
 */
internal enum class MeshServiceCommand {
    RUN,
    STOP,
    ;

    companion object {
        const val ACTION_STOP = "org.xmtp.android.library.mesh.action.STOP"

        fun of(action: String?): MeshServiceCommand = if (action == ACTION_STOP) STOP else RUN
    }
}
