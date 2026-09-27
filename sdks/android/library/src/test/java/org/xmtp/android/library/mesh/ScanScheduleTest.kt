package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.xmtp.android.library.mesh.policy.ScanSchedule
import org.xmtp.android.library.mesh.policy.ScanWindow

class ScanScheduleTest {
    private val s = ScanSchedule()

    @Test
    fun idle_cycle_is_10s_on_20s_off() {
        assertEquals(ScanWindow(10_000, 20_000), s.window(nowMs = 1_000_000, lastSightingMs = null, connectedPeers = 0))
    }

    @Test
    fun recent_sighting_or_connection_scans_faster() {
        assertEquals(ScanWindow(10_000, 5_000), s.window(100_000, lastSightingMs = 50_000, connectedPeers = 0))
        assertEquals(ScanWindow(10_000, 5_000), s.window(100_000, lastSightingMs = null, connectedPeers = 1))
        assertEquals(ScanWindow(10_000, 20_000), s.window(200_000, lastSightingMs = 100_000, connectedPeers = 0))
    }

    @Test
    fun cycles_faster_than_android_scan_throttle_are_rejected() {
        assertThrows(IllegalArgumentException::class.java) { ScanSchedule(nearby = ScanWindow(3_000, 2_000)) }
    }
}
