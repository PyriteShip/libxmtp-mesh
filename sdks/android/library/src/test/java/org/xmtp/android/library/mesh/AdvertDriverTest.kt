package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.AdvertClock.Action
import org.xmtp.android.library.mesh.policy.AdvertDriver
import org.xmtp.android.library.mesh.policy.AdvertSink

/** The radio's route from the node's advert state to the advertiser (DESIGN.md §B14.2). */
class AdvertDriverTest {
    private class FakeSink : AdvertSink {
        val calls = mutableListOf<String>()

        override fun startNewSet(serviceData: ByteArray) {
            calls += "new ${serviceData[1]}/${serviceData[2]}"
        }

        override fun updateData(serviceData: ByteArray) {
            calls += "update ${serviceData[1]}/${serviceData[2]}"
        }

        override fun stop() {
            calls += "stop"
        }
    }

    private fun data(
        flags: Int,
        token: Int,
    ) = byteArrayOf(2, flags.toByte()) + ByteArray(8) { token.toByte() }

    private val sink = FakeSink()
    private val driver = AdvertDriver().also { it.sink = sink }

    @Test
    fun nothingIsAdvertisedBeforeTheServiceIsReady() {
        assertEquals(Action.NEW_SET, driver.onState(10, data(0, 1), 9_900, 3))
        assertEquals(Action.UPDATE_DATA, driver.onState(10, data(2, 1), 9_900, 4))
        assertEquals(emptyList<String>(), sink.calls)
        assertTrue(driver.onServiceReady())
        assertEquals(listOf("new 2/1"), sink.calls)
    }

    @Test
    fun aNewWindowStartsANewSetAndAFlagChangeUpdatesIt() {
        driver.onState(10, data(0, 1), 9_900, 3)
        driver.onServiceReady()
        driver.onState(10, data(2, 1), 9_900, 4)
        driver.onState(10, data(2, 1), 9_900, 5)
        driver.onState(11, data(2, 7), 10_800, 5)
        assertEquals(listOf("new 0/1", "update 2/1", "new 2/7"), sink.calls)
    }

    @Test
    fun stoppingForgetsTheStateAndTheReadiness() {
        driver.onState(10, data(0, 1), 9_900, 3)
        driver.onServiceReady()
        driver.stop()
        assertEquals(listOf("new 0/1", "stop"), sink.calls)
        assertFalse(driver.ready)
        assertEquals(null, driver.clock.serviceData)
        assertEquals(null, driver.sink)
    }

    @Test
    fun readyWithNoStateYetStartsNothing() {
        assertFalse(driver.onServiceReady())
        assertEquals(emptyList<String>(), sink.calls)
        driver.onState(10, data(0, 1), 9_900, 3)
        assertEquals(listOf("new 0/1"), sink.calls)
    }
}
