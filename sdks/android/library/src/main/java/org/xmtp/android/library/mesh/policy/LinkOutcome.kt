package org.xmtp.android.library.mesh.policy

/** The kind of an open link, as the node reports it (DESIGN.md §B14.3). */
enum class LinkKindTag { CONTACT, RELAY, PAIRING }

/** What a link's opening tells the node, and what its close costs the next dial (DESIGN.md §B7.2, §B14.3). */
object LinkOutcome {
    enum class Penalty {
        NONE,

        /** Back off that contact's IK dials (it removed us, or we hold a stale card). */
        CONTACT_BACKOFF,

        /** The contact is reachable: reset its back-off. */
        CONTACT_RESET,

        /** Keep away from that device for the cooldown (best effort: addresses rotate). */
        DEVICE_COOLDOWN,
    }

    /** The role a ready link reports to the node. */
    sealed class Ready {
        /** We accepted it: always Accept, reported before the dialer can send a frame. */
        object Accept : Ready()

        /** We dialed it with [intent]. */
        data class Dial(
            val intent: DialPlanner.Intent,
        ) : Ready()

        /** An outbound link with no dial intent: no role to report, so close it. */
        object Close : Ready()
    }

    /** xmtp_mesh MeshTransport contract: the accepting side reports Accept; a dialer its intent. */
    fun onReady(
        inbound: Boolean,
        dialed: DialPlanner.Intent?,
    ): Ready =
        when {
            inbound -> Ready.Accept
            dialed != null -> Ready.Dial(dialed)
            else -> Ready.Close
        }

    /**
     * Our own power-down costs nothing; a version-1 link Hello (an older phone) cools the device
     * down; any other link that never became ready ([wasReady] false) is a GATT failure, backed
     * off where GATT reports it. A contact dial whose link verified, or whose inbox is verified
     * on another link ([inboxVerifiedElsewhere]: the node superseded this duplicate before
     * verifying it), resets that contact's back-off; one that never verified backs it off. A
     * relay link the node closed cools the device down. Anything else costs nothing.
     */
    fun onClose(
        intent: DialPlanner.Intent?,
        everVerified: Boolean,
        kind: LinkKindTag?,
        nodeRequested: Boolean,
        reason: String,
        wasReady: Boolean = true,
        ownPowerDown: Boolean = false,
        inboxVerifiedElsewhere: Boolean = false,
    ): Penalty =
        when {
            ownPowerDown -> Penalty.NONE
            reason.startsWith(OLD_VERSION_REASON) -> Penalty.DEVICE_COOLDOWN
            !wasReady -> Penalty.NONE
            intent is DialPlanner.Intent.Contact && (everVerified || inboxVerifiedElsewhere) -> Penalty.CONTACT_RESET
            intent is DialPlanner.Intent.Contact -> Penalty.CONTACT_BACKOFF
            nodeRequested && (kind == LinkKindTag.RELAY || intent == DialPlanner.Intent.Relay) ->
                Penalty.DEVICE_COOLDOWN
            else -> Penalty.NONE
        }

    /** The start of ReliableLink's close reason for a link Hello of another version. */
    const val OLD_VERSION_REASON = "link version"
}
