package org.xmtp.android.library.mesh

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xmtp.android.library.Client
import org.xmtp.android.library.ClientOptions
import org.xmtp.android.library.XMTPEnvironment
import org.xmtp.android.library.hexToByteArray
import org.xmtp.android.library.mesh.link.LinkLimits
import org.xmtp.android.library.messages.PrivateKeyBuilder
import uniffi.xmtpv3.FfiException
import uniffi.xmtpv3.FfiLinkRole
import uniffi.xmtpv3.FfiMeshNode
import uniffi.xmtpv3.FfiMeshPresenceCallback
import uniffi.xmtpv3.FfiMeshTransport
import uniffi.xmtpv3.FfiVerifiedPeer
import uniffi.xmtpv3.meshMaxFrameLen
import uniffi.xmtpv3.openMeshNode
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList

@RunWith(AndroidJUnit4::class)
class MeshLoopbackTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val created = CopyOnWriteArrayList<Pair<Client, FfiMeshNode>>()

    /** One link generation as seen from one end: who is across, and the connection ids on both sides. */
    private class Link(
        val peer: LoopEnd,
        val remoteId: String, // what this end's node calls the other end ("b#1")
        val idAtPeer: String, // what the other end's node calls this end ("a#1")
    )

    /**
     * Stand-in for the BLE radio: ordered and lossless while linked. Frames for a
     * stale connection id, or sent while cut, are dropped (that pipe is gone).
     */
    private inner class LoopEnd(
        val name: String,
        val node: FfiMeshNode,
    ) : FfiMeshTransport {
        @Volatile var link: Link? = null
        private val outbox = Channel<Pair<String, ByteArray>>(Channel.UNLIMITED)

        init {
            scope.launch {
                for ((idAtPeer, frame) in outbox) {
                    val l = link ?: continue
                    if (l.idAtPeer == idAtPeer) l.peer.node.onFrame(idAtPeer, frame)
                }
            }
        }

        override fun send(
            peerId: String,
            frame: ByteArray,
        ) {
            val l = link ?: return
            if (l.remoteId == peerId) outbox.trySend(l.idAtPeer to frame)
        }

        /** Like the radio: closing the current link reports it lost on both ends (off the node's thread). */
        override fun disconnect(peerId: String) {
            val l = link ?: return
            if (l.remoteId == peerId) scope.launch { if (link === l) unlink(this@LoopEnd, l.peer) }
        }
    }

    private var generation = 0

    /**
     * [a] dials [b] as [role]. [b] reports Accept first, as the radio does, so its node knows
     * the link before [a]'s first frame arrives.
     */
    private fun link(
        a: LoopEnd,
        b: LoopEnd,
        role: FfiLinkRole,
    ) {
        generation++
        val aId = "${a.name}#$generation"
        val bId = "${b.name}#$generation"
        a.link = Link(b, remoteId = bId, idAtPeer = aId)
        b.link = Link(a, remoteId = aId, idAtPeer = bId)
        b.node.onPeerConnected(aId, FfiLinkRole.Accept)
        a.node.onPeerConnected(bId, role)
    }

    private fun unlink(
        a: LoopEnd,
        b: LoopEnd,
    ) {
        val aSide = a.link ?: return
        val bSide = b.link ?: return
        a.link = null
        b.link = null
        a.node.onPeerLost(aSide.remoteId)
        b.node.onPeerLost(bSide.remoteId)
    }

    private suspend fun meshPeer(name: String): Pair<Client, LoopEnd> {
        val dir = File(context.cacheDir, "mesh-loopback-$name-${System.nanoTime()}").apply { mkdirs() }
        val mesh = MeshOptions(File(dir, "node.db3").absolutePath, SecureRandom().generateSeed(32))
        val options =
            ClientOptions(
                api = ClientOptions.Api(env = XMTPEnvironment.MESH, isSecure = false, mesh = mesh),
                appContext = context,
                dbEncryptionKey = SecureRandom().generateSeed(32),
                dbDirectory = dir.absolutePath,
                deviceSyncEnabled = false,
            )
        val wallet = PrivateKeyBuilder()
        val client = Client.create(wallet, options)
        val end = LoopEnd(name, openMeshNode(mesh.dbPath, mesh.encryptionKey))
        created += client to end.node
        end.node.setAccountKey(
            wallet
                .getPrivateKey()
                .secp256K1.bytes
                .toByteArray(),
        )
        end.node.startSync(client.ffiClientForMesh, end)
        return client to end
    }

    /** A mesh client with no loopback node of its own, for tests that go through [Mesh.start]. */
    private suspend fun meshClient(name: String): Triple<Client, MeshOptions, ByteArray> {
        val dir = File(context.cacheDir, "mesh-loopback-$name-${System.nanoTime()}").apply { mkdirs() }
        val mesh = MeshOptions(File(dir, "node.db3").absolutePath, SecureRandom().generateSeed(32))
        val options =
            ClientOptions(
                api = ClientOptions.Api(env = XMTPEnvironment.MESH, isSecure = false, mesh = mesh),
                appContext = context,
                dbEncryptionKey = SecureRandom().generateSeed(32),
                dbDirectory = dir.absolutePath,
                deviceSyncEnabled = false,
            )
        val wallet = PrivateKeyBuilder()
        val key =
            wallet
                .getPrivateKey()
                .secp256K1.bytes
                .toByteArray()
        return Triple(Client.create(wallet, options), mesh, key)
    }

    private data class Pairing(
        val alix: Client,
        val a: LoopEnd,
        val bo: Client,
        val b: LoopEnd,
    )

    /**
     * Pair two loopback nodes the way two people do (DESIGN.md §B14.4): both in pairing mode,
     * a dials over Noise XX, both confirm the code both nodes show. The pairing link then
     * carries identities and key packages like a contact link.
     */
    private suspend fun pairOverLoopback(
        a: LoopEnd,
        b: LoopEnd,
        bInbox: String,
        aInbox: String,
    ) {
        a.node.setPairingMode(true)
        b.node.setPairingMode(true)
        link(a, b, FfiLinkRole.DialPairing)
        eventually("both nodes show the same code") {
            val pa = a.node.pendingPairings().singleOrNull()
            val pb = b.node.pendingPairings().singleOrNull()
            pa != null && pb != null && pa.code == pb.code
        }
        a.node.confirmPairing(
            a.node
                .pendingPairings()
                .single()
                .peerId,
        )
        b.node.confirmPairing(
            b.node
                .pendingPairings()
                .single()
                .peerId,
        )
        eventually("each stored the other as a contact") {
            a.node.contacts().any { it.inboxId == bInbox } && b.node.contacts().any { it.inboxId == aInbox }
        }
    }

    private suspend fun connectedPair(): Pairing {
        val (alix, a) = meshPeer("a")
        val (bo, b) = meshPeer("b")
        // Not linked yet: neither node can have the other's key package.
        assertFalse(alix.meshCanMessage(bo.installationId.hexToByteArray()))
        pairOverLoopback(a, b, bo.inboxId, alix.inboxId)
        eventually("mutual mesh auth") {
            a.node.authenticatedPeers() == listOf(a.link!!.remoteId) &&
                b.node.authenticatedPeers() == listOf(b.link!!.remoteId)
        }
        eventually("each node holds the other's key package") {
            alix.meshCanMessage(bo.installationId.hexToByteArray()) &&
                bo.meshCanMessage(alix.installationId.hexToByteArray())
        }
        return Pairing(alix, a, bo, b)
    }

    /** Stops each node's sync sessions and frees the nodes and clients, so no test leaks tasks into the next. */
    @After
    fun tearDown() {
        scope.cancel()
        for ((client, node) in created) {
            runCatching { node.stopSync() }
            runCatching { node.close() }
            runCatching { client.ffiClientForMesh.close() }
        }
        created.clear()
    }

    /**
     * The relay switch reaches the running node and toggles live, with no radio
     * restart. Needs the Nearby-devices runtime permissions already granted to the test APK.
     */
    @Test
    fun relayTogglesThroughTheNodeWithoutRestartingTheRadio() =
        runBlocking {
            val (client, options, key) = meshClient("relay")
            try {
                // Assumes the test device is charging or above 15% battery, or MeshRelayPolicy
                // would pause the relay regardless of the userEnabled toggle asserted below.
                val radio = Mesh.start(context, client, options, key.copyOf(), relay = true)
                assertTrue(Mesh.relay.value.active)
                Mesh.setRelayEnabled(false)
                assertFalse(Mesh.relay.value.active)
                assertSame(radio, Mesh.radio)
                Mesh.setRelayEnabled(true)
                assertTrue(Mesh.relay.value.active)
                assertSame(radio, Mesh.radio)
                Mesh.stop(context)
                assertFalse(Mesh.relay.value.active)
            } finally {
                Mesh.stop(context)
                runCatching { client.ffiClientForMesh.close() }
            }
        }

    /**
     * Signed sequencing over the real bindings (DESIGN.md §B13): one node signs the rows it
     * orders, the other checks them, and nothing is refused.
     */
    @Test
    fun signedSequencingCountersMoveOverLoopback() =
        runBlocking {
            val (alix, a, bo, b) = connectedPair()
            val dm = retrying("create DM", 60_000) { alix.conversations.findOrCreateDm(bo.inboxId) }
            dm.send("signed hello")
            eventually("bo receives") { hasMessage(bo, "signed hello") }
            val sa = a.node.meshStats()
            val sb = b.node.meshStats()
            assertTrue("rows signed on some node", sa.seqRowsSigned + sb.seqRowsSigned > 0uL)
            assertTrue("rows checked on some node", sa.seqRowsVerified + sb.seqRowsVerified > 0uL)
            for (s in listOf(sa, sb)) {
                assertEquals(0uL, s.seqRejectedMissingProof)
                assertEquals(0uL, s.seqRejectedBadSignature)
                assertEquals(0uL, s.seqRejectedWrongSigner)
                assertEquals(0uL, s.seqEquivocations)
                assertEquals(0uL, s.peersRejectedVersion)
            }
        }

    /**
     * Mesh.stats() follows the node Mesh.start opens: present while running, null after stop.
     * Rejection counters are not asserted: a nearby phone on an older build may be refused.
     * Needs the Nearby-devices runtime permissions already granted to the test APK.
     */
    @Test
    fun statsFollowTheRunningMesh() =
        runBlocking {
            val (client, options, key) = meshClient("stats")
            try {
                assertNull(Mesh.stats())
                Mesh.start(context, client, options, key.copyOf())
                assertNotNull(Mesh.stats())
                Mesh.stop(context)
                assertNull(Mesh.stats())
            } finally {
                Mesh.stop(context)
                runCatching { client.ffiClientForMesh.close() }
            }
        }

    /** DESIGN.md §B14.1: start_sync refuses a node without the account key. */
    @Test
    fun startSyncNeedsTheAccountKey() =
        runBlocking {
            val dir = File(context.cacheDir, "mesh-loopback-nokey-${System.nanoTime()}").apply { mkdirs() }
            val mesh = MeshOptions(File(dir, "node.db3").absolutePath, SecureRandom().generateSeed(32))
            val options =
                ClientOptions(
                    api = ClientOptions.Api(env = XMTPEnvironment.MESH, isSecure = false, mesh = mesh),
                    appContext = context,
                    dbEncryptionKey = SecureRandom().generateSeed(32),
                    dbDirectory = dir.absolutePath,
                    deviceSyncEnabled = false,
                )
            val client = Client.create(PrivateKeyBuilder(), options)
            val end = LoopEnd("nokey", openMeshNode(mesh.dbPath, mesh.encryptionKey))
            created += client to end.node
            val failure = runCatching { end.node.startSync(client.ffiClientForMesh, end) }.exceptionOrNull()
            assertTrue(
                "startSync without setAccountKey must fail with FfiException, got $failure",
                failure is FfiException,
            )
            // The core's MeshError::NoAccountKey.
            assertTrue(
                "expected the missing-account-key error, got: ${failure?.message}",
                failure?.message?.contains("no account key") == true,
            )
        }

    /**
     * Contacts over the real bindings (DESIGN.md §B14.4): remove closes the contact link, forget
     * drops the row, reset moves the generation. The pairing link is swapped for a contact link
     * first, as the radio's next dial would be (the pairing-link case has its own tests).
     */
    @Test
    fun removeForgetAndResetOverLoopback() =
        runBlocking {
            val (alix, a, bo, b) = connectedPair()
            assertTrue(a.node.contacts().any { it.inboxId == bo.inboxId && !it.autoAdded })
            unlink(a, b)
            link(a, b, FfiLinkRole.DialContact(bo.inboxId))
            eventually("contact link authenticated") {
                a.node.authenticatedPeers() == listOf(a.link!!.remoteId)
            }
            val v = a.node.contactsVersion()
            assertEquals(1u, a.node.resetDiscoveryKey())
            assertTrue(a.node.contactsVersion() > v)
            assertTrue(a.node.removeContact(bo.inboxId))
            eventually("the removed contact's link closes") { a.node.authenticatedPeers().isEmpty() }
            assertTrue(a.node.contacts().none { it.inboxId == bo.inboxId })
            assertTrue(a.node.forgetContact(bo.inboxId))
            assertFalse(a.node.forgetContact(bo.inboxId))
            assertTrue(b.node.contacts().any { it.inboxId == alix.inboxId })
            assertEquals(1uL, a.node.meshStats().discoveryResets)
        }

    /**
     * Removing or forgetting a contact right after pairing, while the pairing link is still up,
     * closes that link too (DESIGN.md §B14.4).
     */
    private suspend fun closesThePairingLinkOn(forget: Boolean) {
        val (_, a, bo, _) = connectedPair()
        val pairingLink = a.link!!.remoteId
        assertEquals(listOf(pairingLink), a.node.authenticatedPeers())
        if (forget) {
            assertTrue(a.node.forgetContact(bo.inboxId))
        } else {
            assertTrue(a.node.removeContact(bo.inboxId))
        }
        eventually("the pairing link closes") { a.node.authenticatedPeers().isEmpty() && a.link == null }
        assertTrue(a.node.contacts().none { it.inboxId == bo.inboxId })
    }

    @Test
    fun removingAContactClosesThePairingLink() = runBlocking { closesThePairingLinkOn(forget = false) }

    @Test
    fun forgettingAContactClosesThePairingLink() = runBlocking { closesThePairingLinkOn(forget = true) }

    @Test
    fun frameLimitsAgree() {
        assertEquals(LinkLimits.MAX_FRAME_BYTES.toLong(), meshMaxFrameLen().toLong())
    }

    @Test
    fun dmRoundTripOverLoopback() =
        runBlocking {
            val (alix, _, bo, _) = connectedPair()
            val dm = retrying("create DM", 60_000) { alix.conversations.findOrCreateDm(bo.inboxId) }
            dm.send("hello mesh")
            eventually("bo receives") { hasMessage(bo, "hello mesh") }
            // bo is not the sequencer: under BLE-like latency send may throw SyncFailedToWait
            // while the message stays queued (DESIGN.md §B5.5, delivery semantics), so do not require success.
            runCatching {
                bo.conversations
                    .listDms()
                    .first()
                    .send("hello back")
            }
            eventually("alix receives the reply") { hasMessage(alix, "hello back") }
        }

    @Test
    fun presenceReportsVerifiedPeerAndLoss() =
        runBlocking {
            val (_, a, bo, b) = connectedPair()
            val events = CopyOnWriteArrayList<String>()
            val stream =
                a.node.streamPresence(
                    object : FfiMeshPresenceCallback {
                        override fun onPeerVerified(peer: FfiVerifiedPeer) {
                            events += "verified ${peer.peerId} ${peer.inboxId}"
                        }

                        override fun onPeerLost(peerId: String) {
                            events += "lost $peerId"
                        }
                    },
                )
            val first = a.link!!.remoteId
            eventually("bo verified at alix's node") {
                a.node.verifiedPeers().map { it.peerId to it.inboxId } == listOf(first to bo.inboxId)
            }
            // The stream takes its first snapshot on a spawned task; if the link were cut before
            // that ran, it would (correctly) coalesce the history and never report `first`.
            eventually("presence stream reported bo") { events.toList() == listOf("verified $first ${bo.inboxId}") }
            unlink(a, b)
            link(a, b, FfiLinkRole.DialContact(bo.inboxId)) // reconnect: a fresh connection id
            val second = a.link!!.remoteId
            assertNotEquals(first, second)
            eventually("bo re-verified under the new connection id") {
                a.node.verifiedPeers().map { it.peerId } == listOf(second)
            }
            eventually("presence stream saw verify, loss, re-verify") {
                events.toList() ==
                    listOf("verified $first ${bo.inboxId}", "lost $first", "verified $second ${bo.inboxId}")
            }
            stream.end()
            a.node.stopSync()
            assertTrue(a.node.verifiedPeers().isEmpty())
            assertTrue(a.node.authenticatedPeers().isEmpty())
        }

    @Test
    fun messageSentWhilePartitionedArrivesAfterReconnect() =
        runBlocking {
            val (alix, a, bo, b) = connectedPair()
            val dm = retrying("create DM", 60_000) { alix.conversations.findOrCreateDm(bo.inboxId) }
            dm.send("before")
            eventually("first message") { hasMessage(bo, "before") }

            unlink(a, b)
            eventually("sessions dropped") {
                a.node.authenticatedPeers().isEmpty() && b.node.authenticatedPeers().isEmpty()
            }
            // alix created the DM, so alix's node is the sequencer; bo's message must queue.
            // send() may fail with SyncFailedToWait meanwhile: that means "queued", not failed.
            val boDm = bo.conversations.listDms().first()
            val sending = scope.launch { runCatching { boDm.send("while apart") } }
            delay(2_000)
            assertFalse(hasMessage(alix, "while apart"))

            link(a, b, FfiLinkRole.DialContact(bo.inboxId)) // fresh connection ids, as a real reconnect gets
            eventually("queued message delivered after reconnect", 120_000) { hasMessage(alix, "while apart") }
            sending.cancel()
        }
}
