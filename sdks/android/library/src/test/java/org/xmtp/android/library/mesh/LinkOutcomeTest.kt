package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test
import org.xmtp.android.library.mesh.policy.DialPlanner.Intent
import org.xmtp.android.library.mesh.policy.LinkKindTag
import org.xmtp.android.library.mesh.policy.LinkOutcome
import org.xmtp.android.library.mesh.policy.LinkOutcome.Penalty
import org.xmtp.android.library.mesh.policy.LinkOutcome.Ready

/** What a closed link costs the radio's next dial (DESIGN.md §B7.2, §B14.3). */
class LinkOutcomeTest {
    /** One phone removed or reset the other: our IK dial keeps failing; back off that contact, don't churn. */
    @Test
    fun anIkDialThatNeverVerifiedBacksOffThatContact() {
        assertEquals(
            Penalty.CONTACT_BACKOFF,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = false,
                kind = null,
                nodeRequested = true,
                reason = "mesh node requested disconnect",
            ),
        )
        assertEquals(
            Penalty.CONTACT_BACKOFF,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = false,
                kind = null,
                nodeRequested = false,
                reason = "gatt closed, status 8",
            ),
        )
    }

    /** Both phones dialed; the node closed the loser after it verified. That is not a failure: it resets the back-off. */
    @Test
    fun aDuplicateContactLinkClosedByTheNodeIsNotBackedOff() {
        assertEquals(
            Penalty.CONTACT_RESET,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = true,
                kind = LinkKindTag.CONTACT,
                nodeRequested = true,
                reason = "mesh node requested disconnect",
            ),
        )
        assertEquals(
            Penalty.NONE,
            LinkOutcome.onClose(
                null,
                everVerified = true,
                kind = LinkKindTag.CONTACT,
                nodeRequested = true,
                reason = "mesh node requested disconnect",
            ),
        )
    }

    /** Idle, lifetime cap, relay off: the node ends a relay link; don't redial that device at once. */
    @Test
    fun aRelayLinkTheNodeClosedCoolsDownThatDevice() {
        assertEquals(
            Penalty.DEVICE_COOLDOWN,
            LinkOutcome.onClose(
                Intent.Relay,
                everVerified = false,
                kind = LinkKindTag.RELAY,
                nodeRequested = true,
                reason = "mesh node requested disconnect",
            ),
        )
        assertEquals(
            Penalty.DEVICE_COOLDOWN,
            LinkOutcome.onClose(
                null,
                everVerified = false,
                kind = LinkKindTag.RELAY,
                nodeRequested = true,
                reason = "mesh node requested disconnect",
            ),
        )
        assertEquals(
            Penalty.NONE,
            LinkOutcome.onClose(
                Intent.Relay,
                everVerified = false,
                kind = LinkKindTag.RELAY,
                nodeRequested = false,
                reason = "gatt closed, status 19",
            ),
        )
    }

    /** A mesh.10 phone: its link Hello is version 1. Cool the device down: no reconnect loop. */
    @Test
    fun aVersion1HelloCoolsDownTheDevice() {
        assertEquals(
            Penalty.DEVICE_COOLDOWN,
            LinkOutcome.onClose(
                null,
                everVerified = false,
                kind = null,
                nodeRequested = false,
                reason = "link version 1",
            ),
        )
        assertEquals(
            Penalty.DEVICE_COOLDOWN,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = false,
                kind = null,
                nodeRequested = false,
                reason = "link version 1",
            ),
        )
    }

    /** The accepting side always reports Accept (xmtp_mesh MeshTransport contract), whatever it once dialed. */
    @Test
    fun anInboundLinkIsAccepted() {
        assertEquals(Ready.Accept, LinkOutcome.onReady(inbound = true, dialed = null))
        assertEquals(Ready.Accept, LinkOutcome.onReady(inbound = true, dialed = Intent.Relay))
    }

    /** An outbound link reports the role we dialed it with. */
    @Test
    fun anOutboundLinkReportsItsDialIntent() {
        assertEquals(
            Ready.Dial(Intent.Contact("bob")),
            LinkOutcome.onReady(inbound = false, dialed = Intent.Contact("bob")),
        )
        assertEquals(Ready.Dial(Intent.Pairing), LinkOutcome.onReady(inbound = false, dialed = Intent.Pairing))
    }

    /** An outbound link we never meant to dial has no role to report: close it, never guess one. */
    @Test
    fun anOutboundLinkWithoutADialIntentIsClosed() {
        assertEquals(Ready.Close, LinkOutcome.onReady(inbound = false, dialed = null))
    }

    /**
     * The node supersedes a duplicate contact link before it verifies it (no PeerVerified for the
     * loser). With another link to the same inbox verified, that close is a success, not an IK failure.
     */
    @Test
    fun aContactLinkClosedWhileItsInboxIsVerifiedElsewhereIsASuccess() {
        assertEquals(
            Penalty.CONTACT_RESET,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = false,
                kind = null,
                nodeRequested = true,
                reason = "mesh node requested disconnect",
                inboxVerifiedElsewhere = true,
            ),
        )
        assertEquals(
            Penalty.CONTACT_BACKOFF,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = false,
                kind = null,
                nodeRequested = true,
                reason = "mesh node requested disconnect",
                inboxVerifiedElsewhere = false,
            ),
        )
    }

    /** A link that never became ready is a GATT failure, backed off where GATT reports it; only an old Hello counts here. */
    @Test
    fun aLinkThatNeverBecameReadyCostsNothingHereUnlessItsHelloWasOld() {
        assertEquals(
            Penalty.NONE,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = false,
                kind = null,
                nodeRequested = false,
                reason = "gatt closed, status 8",
                wasReady = false,
            ),
        )
        assertEquals(
            Penalty.NONE,
            LinkOutcome.onClose(
                Intent.Relay,
                everVerified = false,
                kind = null,
                nodeRequested = false,
                reason = "liveness timeout",
                wasReady = false,
            ),
        )
        assertEquals(
            Penalty.DEVICE_COOLDOWN,
            LinkOutcome.onClose(
                null,
                everVerified = false,
                kind = null,
                nodeRequested = false,
                reason = "link version 1",
                wasReady = false,
            ),
        )
    }

    /** Bluetooth off or the radio stopping closes every link: nobody failed. */
    @Test
    fun ourOwnPowerDownCostsNothing() {
        assertEquals(
            Penalty.NONE,
            LinkOutcome.onClose(
                Intent.Contact("bob"),
                everVerified = false,
                kind = null,
                nodeRequested = false,
                reason = "bluetooth off",
                ownPowerDown = true,
            ),
        )
        assertEquals(
            Penalty.NONE,
            LinkOutcome.onClose(
                Intent.Relay,
                everVerified = false,
                kind = LinkKindTag.RELAY,
                nodeRequested = true,
                reason = "radio stopped",
                ownPowerDown = true,
            ),
        )
    }
}
