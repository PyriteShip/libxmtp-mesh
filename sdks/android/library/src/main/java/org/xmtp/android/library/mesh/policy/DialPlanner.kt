package org.xmtp.android.library.mesh.policy

/**
 * Who dials whom, and when (DESIGN.md §B7.2, §B14.2). The phone with the lower advert token
 * dials; the other dials only as a fallback [fallbackAfterMs] after the later of the visit's
 * first sighting and the last link drop, so both rarely dial at once (the node resolves the
 * rest). Relay links go only to strangers that offer relay, only while ours is on, only from
 * the lower token, and never take more than [maxRelayLinks] of the [maxConnections] slots; a
 * contact or pairing dial with every slot taken evicts a relay link. Pure: the radio feeds it
 * and acts on the result.
 */
class DialPlanner(
    val maxConnections: Int = 4,
    val maxRelayLinks: Int = 2,
    val fallbackAfterMs: Long = 45_000,
    val reconnectCooldownMs: Long = 2_000,
    /** Unseen for longer than this, a sighting starts a new visit. */
    val absenceGapMs: Long = 60_000,
) {
    sealed class Intent {
        data class Contact(
            val inboxId: String,
        ) : Intent()

        object Relay : Intent()

        object Pairing : Intent()
    }

    sealed class Decision {
        /** Dial; first close [evictKey] (a relay link's GATT key) if set. */
        data class Dial(
            val intent: Intent,
            val evictKey: String? = null,
        ) : Decision()

        data class Skip(
            val why: String,
        ) : Decision()
    }

    class Inputs(
        val match: AdvertMatch,
        /** The later of this visit's first sighting and the last link drop, for this sighting key. */
        val waitingSinceMs: Long,
        val lastLostMs: Long?,
        val nowMs: Long,
        val relayOn: Boolean,
        /** [isBusy] for this sighting key. */
        val busy: Boolean,
        val backoffAllows: Boolean,
        val openConnections: Int,
        /**
         * Relay links against the cap: open links the node reports as relay, plus our relay
         * dials still connecting or whose kind the node has not reported yet.
         */
        val relayLinks: Int = 0,
        /** The oldest relay link's GATT key, if any. */
        val evictableRelayKey: String? = null,
    )

    fun decide(i: Inputs): Decision {
        val (intent, dialFirst) =
            when (val m = i.match) {
                AdvertMatch.Ignore -> return Decision.Skip("not dialable")
                is AdvertMatch.Contact -> Intent.Contact(m.inboxId) to m.dialFirst
                is AdvertMatch.Pairing -> Intent.Pairing to m.dialFirst
                is AdvertMatch.Stranger -> {
                    if (!i.relayOn || !m.relayOffered) return Decision.Skip("no relay")
                    if (!m.dialFirst) return Decision.Skip("the stranger dials")
                    Intent.Relay to true
                }
            }
        if (i.busy) return Decision.Skip("busy")
        if (!i.backoffAllows) return Decision.Skip("backing off")
        if (i.lastLostMs != null && i.nowMs - i.lastLostMs < reconnectCooldownMs) return Decision.Skip("cooldown")
        if (!dialFirst &&
            i.nowMs - i.waitingSinceMs < fallbackAfterMs
        ) {
            return Decision.Skip("the other phone dials first")
        }
        if (intent == Intent.Relay) {
            if (i.relayLinks >= maxRelayLinks) return Decision.Skip("relay slots full")
            if (i.openConnections >= maxConnections) return Decision.Skip("no free slot")
            return Decision.Dial(intent)
        }
        if (i.openConnections < maxConnections) return Decision.Dial(intent)
        val evict = i.evictableRelayKey ?: return Decision.Skip("no free slot")
        return Decision.Dial(intent, evictKey = evict)
    }

    /** Relay links beyond the cap (the newest ones), to close. */
    fun relayLinksToClose(relayKeysOldestFirst: List<String>): List<String> = relayKeysOldestFirst.drop(maxRelayLinks)

    /**
     * A contact is keyed by its inbox (stable across windows, so the fallback clock and the
     * back-off survive a token change); anything else by the device address it came from.
     */
    fun sightingKey(
        match: AdvertMatch,
        deviceAddress: String,
    ): String? =
        when (match) {
            AdvertMatch.Ignore -> null
            is AdvertMatch.Contact -> CONTACT_PREFIX + match.inboxId
            is AdvertMatch.Stranger, is AdvertMatch.Pairing -> DEVICE_PREFIX + deviceAddress
        }

    /**
     * Busy while a dial to this [dialKey] is in flight or its link is open, or (a contact) while
     * a link verified its inbox, on any device. A relay link to the same device never makes a
     * contact busy: after a reset or a one-sided removal the other phone sees us as a stranger.
     */
    fun isBusy(
        dialKey: String,
        dialedKeys: Collection<String>,
        verifiedInboxes: Collection<String>,
    ): Boolean =
        dialKey in dialedKeys ||
            (
                dialKey.startsWith(CONTACT_PREFIX) &&
                    dialKey.removePrefix(CONTACT_PREFIX).substringBefore('@') in verifiedInboxes
            )

    fun sightingStart(
        firstSeenMs: Long?,
        lastSeenMs: Long?,
        nowMs: Long,
    ): Long = if (firstSeenMs == null || lastSeenMs == null || nowMs - lastSeenMs > absenceGapMs) nowMs else firstSeenMs

    /** Accept an inbound link with a free slot, unless its address is cooling down ([AddressCooldown]). */
    fun acceptInbound(
        openConnections: Int,
        coolingDown: Boolean = false,
    ): Boolean = !coolingDown && openConnections < maxConnections

    companion object {
        const val CONTACT_PREFIX = "c:"
        const val DEVICE_PREFIX = "d:"

        /** The device key of GATT connection [gattKey] ("c:<addr>" or "s:<addr>"). */
        fun deviceKey(gattKey: String): String = DEVICE_PREFIX + gattKey.substringAfter(':')

        /**
         * The contact back-off key: the contact's sighting key and the device it was seen on, so
         * a device replaying a contact's token backs off only itself, never the real contact.
         */
        fun contactBackoffKey(
            contactSightingKey: String,
            deviceAddress: String,
        ): String = "$contactSightingKey@$deviceAddress"

        /**
         * What a dial's back-offs, busy check and last drop are keyed on: a contact per inbox and
         * device ([contactBackoffKey]), so a device replaying a contact's token never blocks our
         * dials to the real contact at another address; anything else by its sighting key.
         */
        fun dialKey(
            sightingKey: String,
            deviceAddress: String,
        ): String =
            if (sightingKey.startsWith(CONTACT_PREFIX)) contactBackoffKey(sightingKey, deviceAddress) else sightingKey

        /** The prefix of every [contactBackoffKey] (and contact [dialKey]) of [inboxId]. */
        fun contactBackoffPrefix(inboxId: String): String = "$CONTACT_PREFIX$inboxId@"
    }
}
