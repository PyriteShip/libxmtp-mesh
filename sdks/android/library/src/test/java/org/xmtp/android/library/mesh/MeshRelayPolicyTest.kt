package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test

class MeshRelayPolicyTest {
    private fun step(
        wasPaused: Boolean,
        percent: Int,
        charging: Boolean = false,
    ) = MeshRelayPolicy.pausedForBattery(wasPaused, percent, charging)

    @Test
    fun pausesOnlyBelowFifteenPercent() {
        assertEquals(false, step(false, 15))
        assertEquals(true, step(false, 14))
    }

    @Test
    fun resumesAtTwentyNotBefore() {
        assertEquals(true, step(true, 16))
        assertEquals(true, step(true, 19))
        assertEquals(false, step(true, 20))
    }

    @Test
    fun chargingNeverPauses() {
        assertEquals(false, step(false, 3, charging = true))
        assertEquals(false, step(true, 3, charging = true))
    }

    @Test
    fun unknownBatteryDoesNotPause() {
        assertEquals(false, step(false, -1))
    }
}
