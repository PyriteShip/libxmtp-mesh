package org.xmtp.android.library.mesh

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The relay switch as the app sees it (DESIGN.md §R8). [active] is what the node is
 * doing: [userEnabled] and not [pausedForBattery]. On by default.
 */
data class MeshRelayState(
    val userEnabled: Boolean,
    val pausedForBattery: Boolean,
    val active: Boolean,
)

/** DESIGN.md §R8: pause below 15% battery; resume at 20% or when charging (hysteresis, no flapping). */
internal object MeshRelayPolicy {
    const val PAUSE_BELOW = 15
    const val RESUME_AT = 20

    /** [percent] < 0 means unknown: never pause on an unknown reading. */
    fun pausedForBattery(
        wasPaused: Boolean,
        percent: Int,
        charging: Boolean,
    ): Boolean =
        when {
            charging || percent < 0 -> false
            wasPaused -> percent < RESUME_AT
            else -> percent < PAUSE_BELOW
        }
}

/** Process-wide relay state, published to [Mesh.relay]. Mutated only under Mesh's lock. */
internal object MeshRelayControl {
    private val state = MutableStateFlow(MeshRelayState(userEnabled = true, pausedForBattery = false, active = false))
    val relay: StateFlow<MeshRelayState> = state.asStateFlow()

    fun current(): MeshRelayState = state.value

    fun update(
        userEnabled: Boolean,
        pausedForBattery: Boolean,
        active: Boolean,
    ) {
        state.value = MeshRelayState(userEnabled, pausedForBattery, active)
    }
}
