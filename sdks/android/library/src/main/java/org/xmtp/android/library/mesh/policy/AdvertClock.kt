package org.xmtp.android.library.mesh.policy

/**
 * When the radio re-reads the node's advert state and what it does with it (DESIGN.md §B14.2).
 * A new window, or a new token inside one (a discovery-key reset), always starts a **new
 * advertising set**, so the platform picks a new random address together with the new token.
 * A flag change inside a window (pairing, relay) changes the data on the running set, so the
 * address and the token stay together.
 */
class AdvertClock {
    enum class Action { NONE, UPDATE_DATA, NEW_SET }

    var window: Long = -1
        private set
    var contactsVersion: Long = -1
        private set
    var serviceData: ByteArray? = null
        private set
    private var nextWindowAtSecs: Long = 0

    /** The earliest read in this window (unix seconds), or null if a read did not say. */
    private var readFromSecs: Long? = null

    fun due(
        nowSecs: Long,
        version: Long,
    ): Boolean = serviceData == null || nowSecs >= nextWindowAtSecs || version != contactsVersion

    fun apply(
        window: Long,
        serviceData: ByteArray,
        nextWindowAtSecs: Long,
        version: Long,
        readAtSecs: Long? = null,
    ): Action {
        val old = this.serviceData
        val action =
            when {
                old == null || window != this.window -> Action.NEW_SET
                !ServiceData.token(serviceData).contentEquals(ServiceData.token(old)) -> Action.NEW_SET
                !serviceData.contentEquals(old) -> Action.UPDATE_DATA
                else -> Action.NONE
            }
        val from = readFromSecs
        readFromSecs =
            if (old == null || window != this.window || from == null || readAtSecs == null) {
                readAtSecs
            } else {
                minOf(from, readAtSecs)
            }
        this.window = window
        this.serviceData = serviceData.copyOf()
        this.nextWindowAtSecs = nextWindowAtSecs
        this.contactsVersion = version
        return action
    }

    /**
     * True if [window] and [contactsVersion] are the node's answer for [nowSecs] at [version]:
     * between this window's first read and its end, at the version read. Anything cached under
     * them is then still valid; otherwise (a window boundary either way, a contacts change, no
     * read yet) it is not.
     */
    fun covers(
        nowSecs: Long,
        version: Long,
    ): Boolean {
        val from = readFromSecs ?: return false
        return serviceData != null && version == contactsVersion && nowSecs >= from && nowSecs < nextWindowAtSecs
    }

    fun delayToNextWindowMs(nowMs: Long): Long = maxOf(0L, nextWindowAtSecs * 1000 - nowMs)

    /** The radio went down: the next state starts a new set. */
    fun reset() {
        window = -1
        contactsVersion = -1
        serviceData = null
        nextWindowAtSecs = 0
        readFromSecs = null
    }
}
