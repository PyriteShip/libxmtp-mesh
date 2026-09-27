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

        override fun disconnect(peerId: String) = Unit
    }

    private var generation = 0

    private fun link(
        a: LoopEnd,
        b: LoopEnd,
    ) {
        generation++
        val aId = "${a.name}#$generation"
        val bId = "${b.name}#$generation"
        a.link = Link(b, remoteId = bId, idAtPeer = aId)
        b.link = Link(a, remoteId = aId, idAtPeer = bId)
        a.node.onPeerConnected(bId)
        b.node.onPeerConnected(aId)
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
        val client = Client.create(PrivateKeyBuilder(), options)
        val end = LoopEnd(name, openMeshNode(mesh.dbPath, mesh.encryptionKey))
        created += client to end.node
        end.node.startSync(client.ffiClientForMesh, end)
        return client to end
    }

    /** A mesh client with no loopback node of its own, for tests that go through [Mesh.start]. */
    private suspend fun meshClient(name: String): Pair<Client, MeshOptions> {
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
        return Client.create(PrivateKeyBuilder(), options) to mesh
    }

    private data class Pairing(
        val alix: Client,
        val a: LoopEnd,
        val bo: Client,
        val b: LoopEnd,
    )

    private suspend fun connectedPair(): Pairing {
        val (alix, a) = meshPeer("a")
        val (bo, b) = meshPeer("b")
        // Not linked yet: neither node can have the other's key package.
        assertFalse(alix.meshCanMessage(bo.installationId.hexToByteArray()))
        link(a, b)
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
            val (client, options) = meshClient("relay")
            try {
                // Assumes the test device is charging or above 15% battery, or MeshRelayPolicy
                // would pause the relay regardless of the userEnabled toggle asserted below.
                val radio = Mesh.start(context, client, options, relay = true)
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
            link(a, b) // reconnect: a fresh connection id
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

            link(a, b) // fresh connection ids, as a real reconnect gets
            eventually("queued message delivered after reconnect", 120_000) { hasMessage(alix, "while apart") }
            sending.cancel()
        }
}
