package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.xmtp.android.library.mesh.ble.AdvertHost
import org.xmtp.android.library.mesh.ble.BleAdvertiser

/** Set lifecycle: stale sets never stay on the air, failed updates fall back to a new set. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleAdvertiserTest {
    private class FakeSet(
        val data: ByteArray,
        val listener: AdvertHost.Listener,
    ) : AdvertHost.Handle {
        var stops = 0
        var inPlace = mutableListOf<ByteArray>()
        var updateThrows = false

        override fun stop() {
            stops++
        }

        override fun setScanResponse(serviceData: ByteArray) {
            if (updateThrows) throw IllegalStateException("no set")
            inPlace += serviceData
        }
    }

    private class FakeHost : AdvertHost {
        val sets = mutableListOf<FakeSet>()

        override fun start(
            serviceData: ByteArray,
            listener: AdvertHost.Listener,
        ): AdvertHost.Handle = FakeSet(serviceData, listener).also { sets += it }
    }

    private val host = FakeHost()
    private val scheduler = FakeScheduler()
    private var current: ByteArray? = null
    private val failures = mutableListOf<Int>()
    private val advertiser = BleAdvertiser(host, scheduler, { current }) { failures += it }

    private fun data(
        flags: Int,
        token: Int,
    ) = byteArrayOf(2, flags.toByte()) + ByteArray(8) { token.toByte() }

    @Test
    fun aFlagChangeOnAStartedSetUpdatesInPlace() {
        advertiser.startNewSet(data(0, 1))
        host.sets[0].listener.onStarted(BleAdvertiser.ADVERTISE_SUCCESS)
        advertiser.updateData(data(2, 1))
        assertEquals(1, host.sets.size)
        assertEquals(
            2,
            host.sets[0]
                .inPlace
                .single()[1]
                .toInt(),
        )
    }

    @Test
    fun anUpdateBeforeTheSetStartedStartsANewSet() {
        advertiser.startNewSet(data(0, 1))
        advertiser.updateData(data(2, 1))
        assertEquals(2, host.sets.size)
        assertEquals(1, host.sets[0].stops)
        assertEquals(2, host.sets[1].data[1].toInt())
    }

    @Test
    fun anUpdateThatThrowsStartsANewSet() {
        advertiser.startNewSet(data(0, 1))
        host.sets[0].listener.onStarted(BleAdvertiser.ADVERTISE_SUCCESS)
        host.sets[0].updateThrows = true
        advertiser.updateData(data(2, 1))
        assertEquals(2, host.sets.size)
        assertEquals(2, host.sets[1].data[1].toInt())
    }

    /** The platform refused the in-place update: a new set with the data the node wants now. */
    @Test
    fun aFailedInPlaceUpdateStartsANewSetWithTheCurrentData() {
        advertiser.startNewSet(data(0, 1))
        host.sets[0].listener.onStarted(BleAdvertiser.ADVERTISE_SUCCESS)
        advertiser.updateData(data(2, 1))
        current = data(3, 1)
        host.sets[0].listener.onScanResponseSet(4)
        assertEquals(2, host.sets.size)
        assertEquals(1, host.sets[0].stops)
        assertEquals(3, host.sets[1].data[1].toInt())
    }

    /** A set replaced before its start callback must not stay on the air with an old token. */
    @Test
    fun aStaleSetThatStartsIsStopped() {
        advertiser.startNewSet(data(0, 1))
        advertiser.startNewSet(data(0, 2))
        assertEquals(1, host.sets[0].stops)
        host.sets[0].listener.onStarted(BleAdvertiser.ADVERTISE_SUCCESS)
        assertEquals(2, host.sets[0].stops)
        // and its late callbacks change nothing
        host.sets[0].listener.onScanResponseSet(4)
        assertEquals(2, host.sets.size)
        assertEquals(0, host.sets[1].stops)
    }

    @Test
    fun aStoppedSetThatStartsIsStopped() {
        advertiser.startNewSet(data(0, 1))
        advertiser.stop()
        host.sets[0].listener.onStarted(BleAdvertiser.ADVERTISE_SUCCESS)
        assertEquals(2, host.sets[0].stops)
        assertEquals(1, host.sets.size)
    }

    /** A transient failure retries with the node's current data, not the data it first tried. */
    @Test
    fun aRetryUsesTheCurrentData() {
        advertiser.startNewSet(data(0, 1))
        current = data(0, 9)
        host.sets[0].listener.onStarted(4)
        scheduler.advanceBy(BleAdvertiser.RETRY_MS)
        assertEquals(2, host.sets.size)
        assertEquals(9, host.sets[1].data[2].toInt())
    }

    @Test
    fun aRetryOfAReplacedSetDoesNothing() {
        advertiser.startNewSet(data(0, 1))
        host.sets[0].listener.onStarted(4)
        advertiser.startNewSet(data(0, 2))
        current = data(0, 3)
        scheduler.advanceBy(BleAdvertiser.RETRY_MS)
        assertEquals(2, host.sets.size)
    }

    @Test
    fun permanentFailuresAreReported() {
        advertiser.startNewSet(data(0, 1))
        host.sets[0].listener.onStarted(BleAdvertiser.ADVERTISE_FAILED_FEATURE_UNSUPPORTED)
        scheduler.advanceBy(BleAdvertiser.RETRY_MS)
        assertEquals(listOf(BleAdvertiser.ADVERTISE_FAILED_FEATURE_UNSUPPORTED), failures)
        assertEquals(1, host.sets.size)
        assertTrue(
            BleAdvertiser(null, scheduler, { null }) { failures += it }.let {
                it.startNewSet(data(0, 1))
                true
            },
        )
        assertEquals(BleAdvertiser.STATUS_NO_ADVERTISER, failures.last())
    }
}
