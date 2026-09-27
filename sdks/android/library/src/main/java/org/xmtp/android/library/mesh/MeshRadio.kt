package org.xmtp.android.library.mesh

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.xmtp.android.library.mesh.ble.BleAdvertiser
import org.xmtp.android.library.mesh.ble.BleScanner
import org.xmtp.android.library.mesh.ble.ConnectionEvents
import org.xmtp.android.library.mesh.ble.GattClientConnection
import org.xmtp.android.library.mesh.ble.GattServerHost
import org.xmtp.android.library.mesh.ble.HandlerScheduler
import org.xmtp.android.library.mesh.link.Cancellable
import org.xmtp.android.library.mesh.link.LinkConfig
import org.xmtp.android.library.mesh.link.LinkLimits
import org.xmtp.android.library.mesh.link.LinkListener
import org.xmtp.android.library.mesh.link.LinkPacket
import org.xmtp.android.library.mesh.link.ReliableLink
import org.xmtp.android.library.mesh.link.ShortId
import org.xmtp.android.library.mesh.link.WriteQueue
import org.xmtp.android.library.mesh.policy.BackoffTracker
import org.xmtp.android.library.mesh.policy.CodedPhyProbe
import org.xmtp.android.library.mesh.policy.ConnectPolicy
import org.xmtp.android.library.mesh.policy.MeshAdvertisement
import org.xmtp.android.library.mesh.policy.MeshPermissions
import org.xmtp.android.library.mesh.policy.PeerTable
import org.xmtp.android.library.mesh.policy.RadioStart
import org.xmtp.android.library.mesh.policy.RestartBackoff
import org.xmtp.android.library.mesh.policy.ScanSchedule
import org.xmtp.android.library.mesh.policy.ScanStartLimiter
import uniffi.xmtpv3.FfiMeshCallbackException
import uniffi.xmtpv3.FfiMeshNode
import uniffi.xmtpv3.FfiMeshPresenceCallback
import uniffi.xmtpv3.FfiMeshPresenceStream
import uniffi.xmtpv3.FfiMeshTransport
import uniffi.xmtpv3.FfiVerifiedPeer
import uniffi.xmtpv3.meshMaxFrameLen

data class MeshRadioConfig(
    val maxConnections: Int = 4,
    val window: Int = 4,
    val ackTimeoutMs: Long = 1_500,
    val maxRetries: Int = 5,
    /** DESIGN.md §B11 defers Coded PHY; when enabled it is still used only after an active probe. */
    val codedPhyProbe: Boolean = false,
    val scanSchedule: ScanSchedule = ScanSchedule(),
    /** See [LinkConfig.keepaliveIntervalMs]. */
    val keepaliveIntervalMs: Long = 8_000,
    /** See [LinkConfig.livenessTimeoutMs]. */
    val livenessTimeoutMs: Long = 24_000,
)

class MeshException(
    message: String,
) : Exception(message)

/**
 * The Android BLE radio: moves whole frames between this phone's mesh node
 * and nearby phones'. All state lives on one HandlerThread; Rust callbacks
 * ([send], [disconnect]) and BLE callbacks hop onto it. The node's
 * onPeerConnected / onFrame / onPeerLost are synchronous and are called
 * directly on that thread, which keeps them in order. [PeerTable] and
 * [CodedPhyProbe] are single-threaded and are only touched on that thread.
 *
 * Rust PeerIds are connection-scoped ("<shortId>#<n>", see [PeerTable]); the
 * short id is only the logical peer identity used for discovery and backoff.
 *
 * A silent peer is detected by the BLE supervision timeout (the stack reports a
 * disconnect, which closes the link), by the link's own ack timeout × (retries + 1)
 * while a frame is in flight, or — a link with nothing in flight, whose remote
 * process died without the transport noticing (D23) — by [ReliableLink]'s own
 * idle liveness timer, which pings the peer and closes with "liveness timeout" if
 * nothing answers.
 */
@SuppressLint("MissingPermission")
class MeshRadio internal constructor(
    context: Context,
    private val node: FfiMeshNode,
    private val localShortId: ByteArray,
    private val config: MeshRadioConfig = MeshRadioConfig(),
) : FfiMeshTransport {
    private val context: Context = context.applicationContext

    /** This phone's short id (lowercase hex): its logical identity in advertisements. */
    val localShortIdHex: String = ShortId.hex(localShortId)

    private val thread = HandlerThread("xmtp-mesh-radio").apply { start() }
    private val handler = Handler(thread.looper)
    private val scheduler = HandlerScheduler(handler)
    private val manager: BluetoothManager = this.context.getSystemService(BluetoothManager::class.java)
    private val adapter: BluetoothAdapter? = manager.adapter

    private val peers = PeerTable(localShortIdHex)
    private val policy = ConnectPolicy(maxConnections = config.maxConnections)
    private val backoff = BackoffTracker()
    private val restartBackoff = RestartBackoff()
    private var restartTimer: Cancellable? = null
    private val links = HashMap<String, LinkSlot>()
    private val clients = HashMap<String, GattClientConnection>()
    private val pendingByKey = HashMap<String, String>() // outbound key -> short id we dialed
    private val sightings = HashMap<String, Sighting>()
    private val lastLost = HashMap<String, Long>()
    private val codedRejectedUntil = HashMap<String, Long>()
    private var lastSightingMs: Long? = null
    private var server: GattServerHost? = null
    private var serviceReady = false
    private var advertiser: BleAdvertiser? = null
    private var scanner: BleScanner? = null
    private var pairingMode = false
    private var radioOn = false

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val connected = MutableStateFlow<Set<String>>(emptySet())
    private val verified = MutableStateFlow<Map<String, FfiVerifiedPeer>>(emptyMap())
    private val up = MutableStateFlow(false)

    private val presenceLock = Any()
    private var presence: FfiMeshPresenceStream? = null

    @Volatile private var stopped = false

    /** Short ids (hex) of phones with a working link. Rust authentication may still be in progress. */
    val connectedPeers: StateFlow<Set<String>> = connected.asStateFlow()

    /**
     * Connections whose installation proved inbox membership (presence for "nearby"),
     * keyed by connection-scoped Rust PeerId. Group by `inboxId` for per-contact UI.
     *
     * A verified peer is not yet messageable: its key package may still be on its way.
     * Before `conversations.findOrCreateDm(inboxId)`, wait for a verified peer **and**
     * `client.meshCanMessage(peer.installationId)`; a DM created earlier never includes
     * the peer, and retrying returns that same DM.
     */
    val verifiedPeers: StateFlow<Map<String, FfiVerifiedPeer>> = verified.asStateFlow()

    /**
     * True while the radio is advertising/scanning. False while Bluetooth is off, after
     * [stop], or while a failed start (GATT server unavailable) is being retried.
     */
    val radioUp: StateFlow<Boolean> = up.asStateFlow()

    private class Sighting(
        var device: BluetoothDevice,
        var firstSeenMs: Long,
        var lastSeenMs: Long,
    )

    private inner class LinkSlot(
        val key: String,
        val role: PeerTable.Role,
        val queue: WriteQueue,
        val expectedShortId: String?,
    ) : LinkListener {
        var link: ReliableLink? = null
        var shortId: String? = null
        var probe: CodedPhyProbe? = null

        override fun onReady(remote: LinkPacket.Hello) = onLinkReady(this, remote)

        override fun onFrame(frame: ByteArray) {
            // Only the peer's active link carries its Rust connection; a losing duplicate is being closed.
            val s = shortId ?: return
            if (peers.activeKey(s) != key) return
            peers.peerIdOf(s)?.let { peerId -> rust("onFrame") { node.onFrame(peerId, frame) } }
        }

        override fun onProbeAck(nonce: Int) {
            probe?.let { applyProbe(this, it.onProbeAck(nonce)) }
        }

        override fun onClosed(reason: String) {
            if (links[key] === this) closeLink(key, reason, sendBye = false)
        }
    }

    /** Called on a tokio worker thread: only updates a StateFlow, never throws. */
    private val presenceListener =
        object : FfiMeshPresenceCallback {
            override fun onPeerVerified(peer: FfiVerifiedPeer) {
                try {
                    if (!stopped) verified.update { it + (peer.peerId to peer) }
                } catch (e: Exception) {
                    Log.w(TAG, "presence update failed", e)
                }
            }

            override fun onPeerLost(peerId: String) {
                try {
                    verified.update { it - peerId }
                } catch (e: Exception) {
                    Log.w(TAG, "presence update failed", e)
                }
            }
        }

    // ---- lifecycle -------------------------------------------------------

    /**
     * Call after `node.startSync(client, this)`. Throws [MeshException] if the frame
     * limits differ, a runtime permission is missing, or the device has no Bluetooth.
     * With Bluetooth off it does not throw: [radioUp] stays false and the radio comes
     * up by itself when Bluetooth turns on.
     */
    fun start() {
        val missing =
            MeshPermissions.required(Build.VERSION.SDK_INT).filter {
                context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
            }
        val decision =
            RadioStart.decide(
                rustMaxFrame = meshMaxFrameLen().toLong(),
                linkMaxFrame = LinkLimits.MAX_FRAME_BYTES.toLong(),
                missingPermissions = missing,
                hasAdapter = adapter != null,
                bluetoothOn = adapter?.isEnabled == true,
            )
        if (decision is RadioStart.Decision.Refuse) throw MeshException(decision.reason)
        if (decision == RadioStart.Decision.WaitForBluetooth) {
            Log.i(TAG, "Bluetooth is off; the radio starts when it turns on")
        }
        scope.launch {
            try {
                val stream = node.streamPresence(presenceListener)
                val keep =
                    synchronized(presenceLock) {
                        if (!stopped) presence = stream
                        !stopped
                    }
                if (!keep) stream.end()
            } catch (e: Exception) {
                Log.w(TAG, "presence stream unavailable", e)
            }
        }
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(stateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(stateReceiver, filter)
        }
        // Receiver first, then a re-check on the radio thread: Bluetooth turning on in
        // between is seen by one or the other, and powerUp() is idempotent.
        handler.post { if (!stopped && adapter?.isEnabled == true) powerUp() }
    }

    /**
     * Closes every link (each reported lost to the node) and ends the radio thread.
     * Call `node.stopSync()` first (as [Mesh.stop] does): the node holds this radio as its
     * transport until then, so the two keep each other alive.
     */
    fun stop() {
        val stream =
            synchronized(presenceLock) {
                stopped = true
                presence.also { presence = null }
            }
        runCatching { context.unregisterReceiver(stateReceiver) }
        runCatching { stream?.end() }
        scope.cancel()
        verified.value = emptyMap()
        handler.post {
            powerDown("radio stopped")
            thread.quitSafely()
        }
    }

    fun setPairingMode(enabled: Boolean) {
        handler.post {
            pairingMode = enabled
            if (radioOn && serviceReady) advertiser?.start(advertisement())
        }
    }

    /** Rust connection ids that completed the signed hello. */
    fun authenticatedPeers(): List<String> = node.authenticatedPeers()

    private val stateReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                c: Context,
                intent: Intent,
            ) {
                when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)) {
                    BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF ->
                        handler.post { powerDown("bluetooth off") }
                    BluetoothAdapter.STATE_ON -> handler.post { if (!stopped) powerUp() }
                }
            }
        }

    private fun powerUp() {
        if (radioOn) return
        val adapter = adapter ?: return
        lateinit var gattServer: GattServerHost
        gattServer =
            GattServerHost(context, manager, handler, gattEvents) { ok ->
                // The platform adds the service asynchronously; advertise only once it is served.
                if (server !== gattServer || !radioOn) return@GattServerHost
                when (val next = RadioStart.onServiceAdded(ok)) {
                    RadioStart.ServiceAdded.Advertise -> {
                        restartBackoff.reset()
                        serviceReady = true
                        advertiser?.start(advertisement())
                    }
                    is RadioStart.ServiceAdded.Restart -> {
                        // Never stay dial-out only; retry the whole start
                        // with the same backoff as a failed open() (not reset by this power-down).
                        Log.w(TAG, next.reason)
                        powerDown(next.reason, resetBackoff = false)
                        scheduleRestart()
                    }
                }
            }
        if (!gattServer.open()) {
            scheduleRestart()
            return
        }
        server = gattServer
        advertiser =
            BleAdvertiser(adapter, handler) { code ->
                Log.w(TAG, "advertising unavailable ($code); this phone can only dial out")
            }
        scanner =
            BleScanner(
                adapter = adapter,
                handler = handler,
                scheduler = scheduler,
                schedule = config.scanSchedule,
                onSighting = ::onSighting,
                nearbyState = { lastSightingMs to peers.size },
                startLimiter = ScanStartLimiter.process,
            ).also { it.start() }
        radioOn = true
        up.value = true
        Log.i(TAG, "radio up as $localShortIdHex")
    }

    /** Retries a failed start (1 s doubling to 30 s) until it works, Bluetooth goes off, or [stop]. */
    private fun scheduleRestart() {
        if (stopped || restartTimer != null) return
        val delay = restartBackoff.nextDelayMs()
        Log.w(TAG, "GATT server unavailable; retrying radio start in ${delay}ms")
        restartTimer =
            scheduler.schedule(delay) {
                restartTimer = null
                if (!stopped && adapter?.isEnabled == true) powerUp()
            }
    }

    private fun cancelRestart() {
        restartTimer?.cancel()
        restartTimer = null
        restartBackoff.reset()
    }

    private fun powerDown(
        reason: String,
        resetBackoff: Boolean = true,
    ) {
        if (resetBackoff) {
            cancelRestart()
        } else {
            restartTimer?.cancel()
            restartTimer = null
        }
        if (!radioOn) return
        radioOn = false
        up.value = false
        serviceReady = false
        scanner?.stop()
        advertiser?.stop()
        // No BYE: the transport closes at once (or Bluetooth is already going off), and
        // the remote sees the disconnect through its own GATT callbacks.
        links.keys.toList().forEach { closeLink(it, reason, sendBye = false) }
        clients.values.toList().forEach { it.close() }
        clients.clear()
        pendingByKey.clear()
        server?.close()
        server = null
        scanner = null
        advertiser = null
        Log.i(TAG, "radio down: $reason")
    }

    private fun advertisement() =
        MeshAdvertisement(
            MeshAdvertisement.VERSION,
            if (pairingMode) MeshAdvertisement.FLAG_PAIRING else 0,
            localShortId,
        )

    // ---- discovery -------------------------------------------------------

    private fun onSighting(
        ad: MeshAdvertisement,
        device: BluetoothDevice,
        rssi: Int,
    ) {
        if (!radioOn) return
        val shortId = ShortId.hex(ad.shortId)
        if (shortId == localShortIdHex) return
        val now = scheduler.nowMs()
        lastSightingMs = now
        pruneSightings(now)
        val sighting = sightings.getOrPut(shortId) { Sighting(device, now, now) }
        sighting.firstSeenMs = policy.sightingStart(sighting.firstSeenMs, sighting.lastSeenMs, now)
        sighting.device = device
        sighting.lastSeenMs = now
        // Never dial a phone we already have (or are building) a link to: a same-role
        // duplicate could make both phones close different links.
        val busy =
            peers.activeKey(shortId) != null ||
                pendingByKey.containsValue(shortId) ||
                links.values.any { it.shortId == shortId || (it.shortId == null && it.expectedShortId == shortId) }
        val go =
            policy.shouldConnect(
                localPeerId = localShortIdHex,
                remotePeerId = shortId,
                firstSeenMs = sighting.firstSeenMs,
                lastLostMs = lastLost[shortId],
                nowMs = now,
                hasLinkOrPending = busy,
                openConnections = links.size + pendingByKey.size,
                backoffAllows = backoff.canAttempt(shortId, now),
            )
        if (!go) return
        val conn = GattClientConnection(context, device, handler, gattEvents)
        if (clients.containsKey(conn.key)) return
        Log.i(TAG, "connecting to $shortId (rssi $rssi)")
        clients[conn.key] = conn
        pendingByKey[conn.key] = shortId
        conn.connect()
    }

    private fun pruneSightings(now: Long) {
        if (sightings.size < MAX_SIGHTINGS) return
        val it = sightings.entries.iterator()
        while (it.hasNext()) {
            if (now - it.next().value.lastSeenMs > SIGHTING_TTL_MS) it.remove()
        }
    }

    // ---- GATT events ------------------------------------------------------

    private val gattEvents =
        object : ConnectionEvents {
            override fun onGattReady(
                key: String,
                role: PeerTable.Role,
                mtu: Int,
            ) {
                val expected = pendingByKey.remove(key)
                if (!radioOn) return
                if (role == PeerTable.Role.PERIPHERAL && !policy.acceptInbound(links.size + pendingByKey.size)) {
                    Log.i(TAG, "refusing inbound $key: at ${config.maxConnections} connections")
                    server?.disconnect(key)
                    return
                }
                val queue =
                    WriteQueue(
                        scheduler,
                        // false = not in flight (stack busy); WriteQueue retries it.
                        submit = { packet -> writeTransport(key, role, packet) },
                        onOverflow = { closeLink(key, "write queue overflow", sendBye = false) },
                    )
                val slot = LinkSlot(key, role, queue, expected)
                val link =
                    ReliableLink(
                        config =
                            LinkConfig(
                                localShortId = localShortId,
                                // One chunk per ATT payload: MTU minus the 3-byte ATT header.
                                maxPacketBytes = (mtu - 3).coerceAtLeast(LinkLimits.MIN_ATT_PAYLOAD),
                                window = config.window,
                                ackTimeoutMs = config.ackTimeoutMs,
                                maxRetries = config.maxRetries,
                                codedHint = localCodedHint(),
                                keepaliveIntervalMs = config.keepaliveIntervalMs,
                                livenessTimeoutMs = config.livenessTimeoutMs,
                            ),
                        isCentral = role == PeerTable.Role.CENTRAL,
                        scheduler = scheduler,
                        write = queue::offer,
                        listener = slot,
                    )
                slot.link = link
                links[key] = slot
                link.start()
            }

            override fun onGattPacket(
                key: String,
                packet: ByteArray,
            ) {
                // Keys never seen in onGattReady (or already closed) have no slot: dropped.
                links[key]?.link?.onPacket(packet)
            }

            override fun onGattWriteComplete(key: String) {
                links[key]?.queue?.onWriteComplete()
            }

            override fun onGattPhyUpdate(
                key: String,
                txCoded: Boolean,
                rxCoded: Boolean,
                ok: Boolean,
            ) {
                val slot = links[key] ?: return
                val probe = slot.probe ?: return
                applyProbe(slot, probe.onPhyUpdate(txCoded, rxCoded, ok))
            }

            /**
             * Also reported (status GATT_SUCCESS) when an inbound central unsubscribes
             * from TX while staying connected; either way that link is over.
             */
            override fun onGattClosed(
                key: String,
                status: Int,
            ) {
                val expected = pendingByKey.remove(key)
                if (expected != null) {
                    clients.remove(key)?.close()
                    val delay = backoff.onFailure(expected, scheduler.nowMs())
                    Log.i(TAG, "connect to $expected failed, status $status (133 = GATT_ERROR); retry in ${delay}ms")
                    return
                }
                val slot = links[key]
                if (slot != null && slot.shortId == null) {
                    slot.expectedShortId?.let { backoff.onFailure(it, scheduler.nowMs()) }
                }
                closeLink(key, "gatt closed, status $status", sendBye = false, transportDelayMs = 0)
            }
        }

    private fun writeTransport(
        key: String,
        role: PeerTable.Role,
        packet: ByteArray,
    ): Boolean =
        if (role == PeerTable.Role.CENTRAL) {
            clients[key]?.write(packet) ?: false
        } else {
            server?.notify(key, packet) ?: false
        }

    // ---- links -----------------------------------------------------------

    private fun onLinkReady(
        slot: LinkSlot,
        hello: LinkPacket.Hello,
    ) {
        val shortId = ShortId.hex(hello.shortId)
        slot.shortId = shortId
        backoff.onSuccess(shortId)
        // D23: a link that has carried nothing inbound recently may be half-open (its
        // remote process died without the transport noticing); prefer the new, just-authenticated
        // link over a stale existing one instead of the usual role tie-break. Each phone judges
        // staleness from its own link's own inbound traffic, not a value the two sides compare —
        // PeerTable.isStale's window is sized so a healthy, merely-idle link
        // never crosses it on either side, so the two phones can only disagree while an existing
        // link is genuinely dying (a narrow race that self-heals on the next redial), never while
        // it's healthy. The side that lost its state entirely (a restarted process) has no
        // existing link to compare against in the first place, so it always takes the new one.
        val existingKey = peers.activeKey(shortId)
        val existingLastInboundMs = existingKey?.let { links[it]?.link?.lastInboundMs }
        val existingIsStale =
            existingKey != null &&
                PeerTable.isStale(existingLastInboundMs, scheduler.nowMs(), config.keepaliveIntervalMs)
        val decision = peers.onLinkReady(shortId, PeerTable.LinkRef(slot.key, slot.role), existingIsStale)
        // Order matters: retire the old Rust connection, announce the new one, then close.
        decision.lostPeerId?.let { old ->
            Log.i(TAG, "peer $shortId: connection $old replaced by ${slot.key}")
            rust("onPeerLost") { node.onPeerLost(old) }
        }
        decision.connectedPeerId?.let { peerId ->
            Log.i(TAG, "peer $shortId connected via ${slot.key} as $peerId")
            rust("onPeerConnected") { node.onPeerConnected(peerId) }
            publishPeers()
        }
        decision.closeKey?.let { closeLink(it, "duplicate link", sendBye = true) }
        if (!decision.keep) return
        maybeProbeCoded(slot, hello)
    }

    private fun closeLink(
        key: String,
        reason: String,
        sendBye: Boolean,
        hard: Boolean = false,
        transportDelayMs: Long = BYE_FLUSH_MS,
    ) {
        // Removed before link.close(), so the listener's onClosed does not re-enter.
        val slot = links.remove(key) ?: return
        Log.i(TAG, "link $key (${slot.shortId}) closed: $reason")
        slot.link?.close(reason, sendBye)
        // Captured now: after the BYE delay the same key (Bluetooth address) may carry a
        // fresh link, which the delayed close must not touch.
        val client = clients[key]
        val host = server
        val closeTransport = {
            slot.queue.close()
            if (slot.role == PeerTable.Role.CENTRAL) {
                if (client != null && clients[key] === client) clients.remove(key)
                client?.close()
            } else if (links[key] == null && server === host) {
                // A closed inbound link must not stay subscribed (the BYE above has
                // been flushed by now), or a re-subscribe over the same ACL is ignored.
                host?.forget(key)
                if (hard) host?.disconnect(key)
            }
        }
        if (sendBye && transportDelayMs > 0) {
            scheduler.schedule(transportDelayMs) { closeTransport() }
        } else {
            closeTransport()
        }
        val shortId = slot.shortId ?: return
        val lostPeerId = peers.onLinkClosed(shortId, key) ?: return
        Log.i(TAG, "peer $shortId lost (connection $lostPeerId)")
        lastLost[shortId] = scheduler.nowMs()
        rust("onPeerLost") { node.onPeerLost(lostPeerId) }
        publishPeers()
    }

    private fun publishPeers() {
        connected.value = peers.peers()
    }

    /** Rust calls are synchronous and never block for long; a panic surfaces as an exception. */
    private inline fun rust(
        what: String,
        block: () -> Unit,
    ) {
        try {
            block()
        } catch (e: Exception) {
            Log.w(TAG, "mesh node rejected $what", e)
        }
    }

    // ---- LE Coded PHY (off unless config.codedPhyProbe) ---------------------

    private fun localCodedHint(): Boolean = Build.VERSION.SDK_INT >= 26 && adapter?.isLeCodedPhySupported == true

    private fun maybeProbeCoded(
        slot: LinkSlot,
        hello: LinkPacket.Hello,
    ) {
        if (!config.codedPhyProbe || slot.role != PeerTable.Role.CENTRAL) return
        if (!hello.codedHint || !localCodedHint()) return
        val shortId = slot.shortId ?: return
        if ((codedRejectedUntil[shortId] ?: 0L) > scheduler.nowMs()) return
        val probe = CodedPhyProbe().also { slot.probe = it }
        // Arm the timeout as the probe starts, so a missing PHY callback still ends it.
        scheduler.schedule(PROBE_TIMEOUT_MS) {
            if (links[slot.key] === slot) applyProbe(slot, probe.onTimeout())
        }
        applyProbe(slot, probe.start())
    }

    private fun applyProbe(
        slot: LinkSlot,
        action: CodedPhyProbe.Action,
    ) {
        val client = clients[slot.key] ?: return
        when (action) {
            CodedPhyProbe.Action.RequestCoded -> client.requestCodedPhy()
            is CodedPhyProbe.Action.SendProbes -> action.nonces.forEach { slot.link?.sendProbe(it) }
            CodedPhyProbe.Action.RevertTo1M -> {
                client.request1mPhy()
                slot.shortId?.let { codedRejectedUntil[it] = scheduler.nowMs() + CODED_RETRY_AFTER_MS }
                Log.i(TAG, "coded PHY rejected for ${slot.shortId}; staying on 1M")
            }
            CodedPhyProbe.Action.None ->
                if (slot.probe?.state == CodedPhyProbe.State.VERIFIED) {
                    Log.i(TAG, "coded PHY verified for ${slot.shortId}")
                }
        }
    }

    // ---- Rust side ---------------------------------------------------------

    /** Called by Rust on a tokio thread. Never blocks: hops onto the radio thread. */
    override fun send(
        peerId: String,
        frame: ByteArray,
    ) {
        if (stopped) return
        post("send") {
            val key = peers.keyForPeerId(peerId)
            if (key == null) {
                // Stale connection id: that pipe is gone and Rust already heard onPeerLost.
                Log.d(TAG, "dropped ${frame.size}-byte frame for $peerId: connection gone")
                return@post
            }
            val link = links[key]?.link ?: return@post
            if (!link.send(frame)) {
                // Only a single frame too large for this link gets here (a full queue holds
                // frames instead). An ordered pipe must not silently lose a frame: end the
                // connection instead. Rust gets onPeerLost and resyncs on the next connection.
                closeLink(key, "frame of ${frame.size} bytes does not fit this link", sendBye = true)
            } else if (link.overQueueCap) {
                Log.w(TAG, "link $key: send queue past its soft cap; holding ${frame.size}-byte frame")
            }
        }
    }

    /** Called by Rust when a connection fails authentication or membership checks. */
    override fun disconnect(peerId: String) {
        if (stopped) return
        post("disconnect") {
            // A stale id must never close a newer connection to the same phone.
            val key = peers.keyForPeerId(peerId) ?: return@post
            peers.shortIdOf(peerId)?.let { backoff.penalize(it, scheduler.nowMs()) }
            closeLink(key, "mesh node requested disconnect", sendBye = true, hard = true)
        }
    }

    /** Hands [block] to the radio thread; errors reach Rust as [FfiMeshCallbackException.Failed]. */
    private fun post(
        what: String,
        block: () -> Unit,
    ) {
        val posted =
            try {
                handler.post {
                    try {
                        block()
                    } catch (e: Exception) {
                        Log.w(TAG, "$what failed on the radio thread", e)
                    }
                }
            } catch (e: Exception) {
                throw FfiMeshCallbackException.Failed(err = "$what: ${e.message}")
            }
        if (!posted) throw FfiMeshCallbackException.Failed(err = "$what: radio thread has stopped")
    }

    private companion object {
        const val TAG = "MeshRadio"
        const val BYE_FLUSH_MS = 300L
        const val PROBE_TIMEOUT_MS = 5_000L
        const val CODED_RETRY_AFTER_MS = 60 * 60 * 1000L
        const val MAX_SIGHTINGS = 256
        const val SIGHTING_TTL_MS = 10 * 60 * 1000L
    }
}
