package org.xmtp.android.library.mesh

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xmtp.android.library.Client
import org.xmtp.android.library.ClientOptions
import org.xmtp.android.library.XMTPEnvironment
import org.xmtp.android.library.libxmtp.DecodedMessage
import org.xmtp.android.library.messages.PrivateKeyBuilder
import uniffi.xmtpv3.openMeshNode
import java.io.File

/**
 * Runs on two phones at once via dev/mesh-two-device-test. Skipped otherwise.
 * alpha creates the DM (and is its sequencer) and sends a ping; bravo answers with a pong.
 */
@RunWith(AndroidJUnit4::class)
class MeshTwoDeviceTest {
    private val alphaKey = ByteArray(32) { 0x11 }
    private val bravoKey = ByteArray(32) { 0x22 }
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val t0 = System.currentTimeMillis()

    private fun role(): String {
        val role = InstrumentationRegistry.getArguments().getString("meshRole")
        assumeTrue("run via sdks/android/dev/mesh-two-device-test", role == "alpha" || role == "bravo")
        return role!!
    }

    /** Phase timings for the field notes; the runner collects this tag from logcat. */
    private fun mark(what: String) = Log.i(TAG, "+${System.currentTimeMillis() - t0}ms $what")

    private class Peer(
        val client: Client,
        val mesh: MeshOptions,
        val otherInbox: String,
    )

    private suspend fun peer(
        role: String,
        dirName: String,
    ): Peer {
        val (mine, theirs) = if (role == "alpha") alphaKey to bravoKey else bravoKey to alphaKey
        val dir =
            File(context.filesDir, dirName).apply {
                deleteRecursively()
                mkdirs()
            }
        val mesh = MeshOptions(File(dir, "node.db3").absolutePath, ByteArray(32) { 7 })
        val api = ClientOptions.Api(env = XMTPEnvironment.MESH, isSecure = false, mesh = mesh)
        val options =
            ClientOptions(
                api,
                appContext = context,
                dbEncryptionKey = ByteArray(32) { 5 },
                dbDirectory = dir.absolutePath,
                deviceSyncEnabled = false,
            )
        val client = Client.create(PrivateKeyBuilder(PrivateKeyBuilder.buildFromPrivateKeyData(mine)), options)
        val otherInbox =
            Client.getOrCreateInboxId(
                api,
                PrivateKeyBuilder(PrivateKeyBuilder.buildFromPrivateKeyData(theirs)).publicIdentity,
            )
        return Peer(client, mesh, otherInbox)
    }

    @Test
    fun pingPongOverBle() =
        runBlocking {
            val role = role()
            val peer = peer(role, "mesh-two-device")
            val client = peer.client
            val otherInbox = peer.otherInbox
            val mesh = peer.mesh
            val node = openMeshNode(mesh.dbPath, mesh.encryptionKey)
            val radio = MeshRadio(context, node, MeshIdentity.shortId(context, File(mesh.dbPath).name))
            node.startSync(client.ffiClientForMesh, radio)
            radio.start()
            mark("$role radio started as ${radio.localShortIdHex}")
            try {
                eventually("BLE link and mesh auth", 180_000) {
                    radio.connectedPeers.value.isNotEmpty() && radio.authenticatedPeers().isNotEmpty()
                }
                mark("linked and authenticated")
                eventually("presence: the other phone's inbox is verified", 60_000) {
                    radio.verifiedPeers.value.values
                        .any { it.inboxId == otherInbox }
                }
                mark("other inbox verified")
                if (role == "alpha") {
                    // A DM created before the peer's key package is here never includes the peer.
                    eventually("the other phone's key package reached this node", 120_000) {
                        radio.verifiedPeers.value.values
                            .filter { it.inboxId == otherInbox }
                            .any { client.meshCanMessage(it.installationId) }
                    }
                    mark("holds bravo's key package")
                    val dm = retrying("create DM", 120_000) { client.conversations.findOrCreateDm(otherInbox) }
                    runCatching { dm.send("ping-from-alpha") }
                    mark("ping sent")
                    eventually("pong", 180_000) { hasMessage(client, "pong-from-bravo") }
                    mark("pong received")
                    delay(10_000) // alpha sequenced the pong; let its echo reach bravo before the link drops
                } else {
                    eventually("ping", 180_000) { hasMessage(client, "ping-from-alpha") }
                    mark("ping received")
                    val dm = client.conversations.listDms().first()
                    runCatching { dm.send("pong-from-bravo") }
                    mark("pong sent")
                    eventually("pong sequenced by alpha", 180_000) {
                        dm.sync()
                        dm.messages().any {
                            it.body == "pong-from-bravo" &&
                                it.deliveryStatus == DecodedMessage.MessageDeliveryStatus.PUBLISHED
                        }
                    }
                    mark("pong published")
                    delay(10_000) // let alpha finish reading before the link drops
                }
            } finally {
                node.stopSync()
                radio.stop()
            }
        }

    /**
     * Mesh.start → stop → start in one process: the radio comes back up,
     * reconnects to the other phone (which runs this test at the same time), and the peer
     * reappears under a PeerId never used before the restart.
     */
    @Test
    fun meshRestartReconnects() =
        runBlocking {
            val role = role()
            val peer = peer(role, "mesh-two-device-restart")
            val seenBefore = HashSet<String>()
            try {
                val first = Mesh.start(context, peer.client, peer.mesh)
                eventually("radio up (first start)", 30_000) { first.radioUp.value }
                mark("$role first start: radio up")
                delay(5_000)
                seenBefore += first.verifiedPeers.value.keys
                Mesh.stop(context)
                eventually("radio down after stop", 30_000) { !first.radioUp.value }
                mark("stopped (peers seen before restart: $seenBefore)")

                val second = Mesh.start(context, peer.client, peer.mesh)
                assertNotSame(first, second)
                eventually("radio up (second start)", 30_000) { second.radioUp.value }
                mark("second start: radio up")
                eventually("other phone verified after restart", 240_000) {
                    second.verifiedPeers.value.values
                        .any { it.inboxId == peer.otherInbox }
                }
                val ids =
                    second.verifiedPeers.value
                        .filterValues { it.inboxId == peer.otherInbox }
                        .keys
                mark("other phone verified after restart as $ids")
                assertTrue("PeerId reused across Mesh.stop/start: $ids vs $seenBefore", ids.none { it in seenBefore })
                delay(20_000) // stay up so the other phone can also finish its restart and reconnect
            } finally {
                Mesh.stop(context)
            }
        }

    private companion object {
        const val TAG = "MeshTwoDeviceTest"
    }
}
