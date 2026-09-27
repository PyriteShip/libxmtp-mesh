package org.xmtp.android.library.mesh

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Whether [MeshForegroundService] currently holds foreground status. False after the
 * platform refused startForeground (background start, missing permission): the radio then
 * runs without foreground protection and the OS may throttle or kill it.
 */
object MeshForeground {
    private val state = MutableStateFlow(false)
    val active: StateFlow<Boolean> = state.asStateFlow()

    internal fun onStartResult(ok: Boolean) {
        state.value = ok
    }

    internal fun onStopped() {
        state.value = false
    }
}
