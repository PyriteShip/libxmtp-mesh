package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.RadioStart

class RadioStartTest {
    private fun decide(
        rustMax: Long = 1024 * 1024,
        missing: List<String> = emptyList(),
        hasAdapter: Boolean = true,
        bluetoothOn: Boolean = true,
    ) = RadioStart.decide(rustMax, 1024 * 1024, missing, hasAdapter, bluetoothOn)

    @Test
    fun bluetooth_on_powers_up() {
        assertEquals(RadioStart.Decision.PowerUp, decide())
    }

    /** Bluetooth off is not an error; the radio waits (radioUp = false). */
    @Test
    fun bluetooth_off_waits_instead_of_refusing() {
        assertEquals(RadioStart.Decision.WaitForBluetooth, decide(bluetoothOn = false))
    }

    @Test
    fun frame_limit_mismatch_refuses() {
        val d = decide(rustMax = 1)
        assertTrue(d is RadioStart.Decision.Refuse && d.reason.contains("frame limit mismatch"))
    }

    @Test
    fun missing_permissions_refuse_even_with_bluetooth_off() {
        val d = decide(missing = listOf("android.permission.BLUETOOTH_SCAN"), bluetoothOn = false)
        assertTrue(d is RadioStart.Decision.Refuse && d.reason.contains("BLUETOOTH_SCAN"))
    }

    @Test
    fun no_adapter_refuses() {
        val d = decide(hasAdapter = false, bluetoothOn = false)
        assertTrue(d is RadioStart.Decision.Refuse && d.reason.contains("no Bluetooth"))
    }

    /** An async addService failure used to leave the phone dial-out only until a BT toggle. */
    @Test
    fun service_added_advertises() {
        assertEquals(RadioStart.ServiceAdded.Advertise, RadioStart.onServiceAdded(true))
    }

    @Test
    fun service_add_failure_restarts_the_radio() {
        val d = RadioStart.onServiceAdded(false)
        assertTrue(d is RadioStart.ServiceAdded.Restart && d.reason.contains("service not added"))
    }
}
