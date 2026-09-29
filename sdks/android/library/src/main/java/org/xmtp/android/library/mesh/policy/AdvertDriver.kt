package org.xmtp.android.library.mesh.policy

/** What the radio advertises with (the BLE advertiser, or a fake in tests). */
internal interface AdvertSink {
    /** A new advertising set: the platform picks a new random address. */
    fun startNewSet(serviceData: ByteArray)

    /** New data on the running set: same address, same token. */
    fun updateData(serviceData: ByteArray)

    fun stop()
}

/**
 * Routes each advert-state read through [clock] to the [AdvertSink] (DESIGN.md §B14.2). Nothing
 * is advertised until the GATT service is served ([onServiceReady]); from then on a new window or
 * token starts a new set and a flag change updates the running one. Radio thread only.
 */
internal class AdvertDriver(
    val clock: AdvertClock = AdvertClock(),
) {
    var sink: AdvertSink? = null
    var ready: Boolean = false
        private set

    /** Applies a fresh read to [clock] and, once ready, to the sink. Returns the clock's action. */
    fun onState(
        window: Long,
        serviceData: ByteArray,
        nextWindowAtSecs: Long,
        version: Long,
        readAtSecs: Long? = null,
    ): AdvertClock.Action {
        val action = clock.apply(window, serviceData, nextWindowAtSecs, version, readAtSecs)
        if (!ready) return action
        val data = clock.serviceData ?: return action
        when (action) {
            AdvertClock.Action.NEW_SET -> sink?.startNewSet(data)
            AdvertClock.Action.UPDATE_DATA -> sink?.updateData(data)
            AdvertClock.Action.NONE -> Unit
        }
        return action
    }

    /** The GATT service is served: advertise the latest state on a new set. True if a set started. */
    fun onServiceReady(): Boolean {
        ready = true
        val data = clock.serviceData ?: return false
        val s = sink ?: return false
        s.startNewSet(data)
        return true
    }

    /** The radio went down: stop advertising and forget the state, so the next read starts a new set. */
    fun stop() {
        sink?.stop()
        sink = null
        ready = false
        clock.reset()
    }
}
