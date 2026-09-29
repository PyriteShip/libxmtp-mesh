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
import org.xmtp.android.library.mesh.ble.WindowAlarm
import org.xmtp.android.library.mesh.link.Cancellable
import org.xmtp.android.library.mesh.link.LinkConfig
import org.xmtp.android.library.mesh.link.LinkLimits
import org.xmtp.android.library.mesh.link.LinkListener
import org.xmtp.android.library.mesh.link.LinkPacket
import org.xmtp.android.library.mesh.link.ReliableLink
import org.xmtp.android.library.mesh.link.WriteQueue
import org.xmtp.android.library.mesh.policy.AddressCooldown
import org.xmtp.android.library.mesh.policy.AdvertCache
import org.xmtp.android.library.mesh.policy.AdvertClock
import org.xmtp.android.library.mesh.policy.AdvertDriver
import org.xmtp.android.library.mesh.policy.AdvertMatch
import org.xmtp.android.library.mesh.policy.BackoffTracker
import org.xmtp.android.library.mesh.policy.CodedPhyProbe
import org.xmtp.android.library.mesh.policy.DialPlanner
import org.xmtp.android.library.mesh.policy.LinkKindTag
import org.xmtp.android.library.mesh.policy.LinkOutcome
import org.xmtp.android.library.mesh.policy.MeshPermissions
import org.xmtp.android.library.mesh.policy.PeerTable
import org.xmtp.android.library.mesh.policy.RadioStart
import org.xmtp.android.library.mesh.policy.RestartBackoff
import org.xmtp.android.library.mesh.policy.ScanSchedule
import org.xmtp.android.library.mesh.policy.ScanStartLimiter
import org.xmtp.android.library.mesh.policy.ServiceData
import uniffi.xmtpv3.FfiAdvertMatch
import uniffi.xmtpv3.FfiLinkKind
import uniffi.xmtpv3.FfiLinkRole
import uniffi.xmtpv3.FfiMeshCallbackException
import uniffi.xmtpv3.FfiMeshNode
import uniffi.xmtpv3.FfiMeshPresenceCallback
import uniffi.xmtpv3.FfiMeshPresenceStream
import uniffi.xmtpv3.FfiMeshTransport
import uniffi.xmtpv3.FfiVerifiedPeer
import uniffi.xmtpv3.meshMaxFrameLen
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

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
 * Rust PeerIds are connection-scoped (`"p#<n>"`, see [PeerTable]). The radio has no
 * stable peer identity (DESIGN.md §B14): it advertises the node's service data, dials by
 * `classifyAdvert`, and tells the node each link's role.
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
    private val config: MeshRadioConfig = MeshRadioConfig(),
) : FfiMeshTransport {
    private val context: Context = context.applicationContext

    private val thread = HandlerThread("xmtp-mesh-radio").apply { start() }
    private val handler = Handler(thread.looper)
    private val scheduler = HandlerScheduler(handler)
    private val manager: BluetoothManager = this.context.getSystemService(BluetoothManager::class.java)
    private val adapter: BluetoothAdapter? = manager.adapter

    private val peers = PeerTable()
    private val planner = DialPlanner(maxConnections = config.maxConnections)
    private val backoff = BackoffTracker()

    /** IK dials to a contact that came up but never verified (DESIGN.md §B7.2): 30 s doubling to 10 min. */
    private val contactBackoff = BackoffTracker(baseMs = 30_000, maxMs = 600_000, maxAttempts = 6, cooldownMs = 600_000)

    /** Connection PeerIds that ever verified; written on a tokio thread, read on the radio thread. */
    private val verifiedEver: MutableSet<String> = Collections.newSetFromMap(ConcurrentHashMap())
    private val linkKinds = HashMap<String, LinkKindTag>() // GATT key -> kind, as the node reports it
    private val classifyCache = AdvertCache()

    /** Inbound strangers closed over the relay cap, refused for 30 s (best effort: addresses rotate). */
    private val inboundCooldown = AddressCooldown(periodMs = INBOUND_COOLDOWN_MS)
    private val restartBackoff = RestartBackoff()
    private var restartTimer: Cancellable? = null
    private val links = HashMap<String, LinkSlot>()
    private val clients = HashMap<String, GattClientConnection>()
    private val pendingByKey = HashMap<String, PendingDial>() // outbound GATT key -> what we dialed
    private val sightings = HashMap<String, Sighting>()
    private val lastLost = LinkedHashMap<String, Long>() // dial key -> last link drop
    private val codedRejectedUntil = HashMap<String, Long>()
    private var lastSightingMs: Long? = null
    private var server: GattServerHost? = null
    private var scanner: BleScanner? = null
    private var radioOn = false
    private var ownToken = ByteArray(LinkPacket.TOKEN_BYTES)
    private val advert = AdvertDriver()
    private val advertClock get() = advert.clock
    private var lastSightingCheckMs: Long? = null
    private var tick: Cancellable? = null
    private val windowAlarm =
        WindowAlarm(this.context) { done ->
            val posted =
                handler.post {
                    try {
                        onWindowAlarm()
                    } finally {
                        done()
                    }
                }
            if (!posted) done()
        }
    private val seenAdverts = LinkedHashSet<String>()

    /** An outbound dial: its sighting key (DialPlanner.sightingKey), what we believe the other phone is, and its address. */
    private class PendingDial(
        val sightingKey: String,
        val intent: DialPlanner.Intent,
        val deviceAddress: String,
    ) {
        /** Back-offs, busy and last drop are keyed on this (per inbox and device for a contact). */
        val dialKey: String = DialPlanner.dialKey(sightingKey, deviceAddress)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val connected = MutableStateFlow<Set<String>>(emptySet())
    private val verified = MutableStateFlow<Map<String, FfiVerifiedPeer>>(emptyMap())
    private val up = MutableStateFlow(false)

    private val presenceLock = Any()
    private var presence: FfiMeshPresenceStream? = null

    @Volatile private var stopped = false

    /** Connection PeerIds with a working link. Rust authentication may still be in progress. */
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
     * [stop], or while a failed start (GATT server or the node's advert state unavailable)
     * is being retried.
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
        val dialed: PendingDial?,
    ) : LinkListener {
        var link: ReliableLink? = null
        var peerId: String? = null
        var probe: CodedPhyProbe? = null
        var readyAtMs = 0L

        override fun onReady(remote: LinkPacket.Hello) = onLinkReady(this, remote)

        override fun onFrame(frame: ByteArray) {
            val id = peerId ?: return
            rust("onFrame") { node.onFrame(id, frame) }
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
                    if (!stopped) {
                        verifiedEver.add(peer.peerId)
                        verified.update { it + (peer.peerId to peer) }
                        // Any verified link to this inbox (ours or theirs) resets its back-off.
                        val prefix = DialPlanner.contactBackoffPrefix(peer.inboxId)
                        handler.post { onInboxVerified(prefix) }
                    }
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

    /** Re-read the node's advert now (pairing mode, contacts, a reset or the relay switch changed). */
    internal fun refreshAdvert() {
        handler.post { refreshAdvertIfDue(force = true) }
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
        // No advert, no start: never advertise or send a link Hello with a zero token.
        if (!readAdvertState()) {
            scheduleRestart("advert state unavailable")
            return
        }
        lateinit var gattServer: GattServerHost
        gattServer =
            GattServerHost(context, manager, handler, gattEvents) { ok ->
                // The platform adds the service asynchronously; advertise only once it is served.
                if (server !== gattServer || !radioOn) return@GattServerHost
                when (val next = RadioStart.onServiceAdded(ok)) {
                    RadioStart.ServiceAdded.Advertise -> {
                        restartBackoff.reset()
                        if (advert.onServiceReady()) logAdvertising()
                    }
                    is RadioStart.ServiceAdded.Restart -> {
                        // Never stay dial-out only; retry the whole start
                        // with the same backoff as a failed open() (not reset by this power-down).
                        powerDown(next.reason, resetBackoff = false)
                        scheduleRestart(next.reason)
                    }
                }
            }
        if (!gattServer.open()) {
            scheduleRestart("GATT server unavailable")
            return
        }
        server = gattServer
        advert.sink =
            BleAdvertiser(
                host = BleAdvertiser.platformHost(adapter, handler),
                scheduler = scheduler,
                currentData = { advertClock.serviceData },
            ) { code ->
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
        windowAlarm.arm(advertClock.delayToNextWindowMs(System.currentTimeMillis()))
        scheduleTick()
        Log.i(TAG, "radio up")
    }

    /** Retries a failed start (1 s doubling to 30 s) until it works, Bluetooth goes off, or [stop]. */
    private fun scheduleRestart(reason: String) {
        if (stopped || restartTimer != null) return
        val delay = restartBackoff.nextDelayMs()
        Log.w(TAG, "$reason; retrying radio start in ${delay}ms")
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
        scanner?.stop()
        advert.stop()
        tick?.cancel()
        tick = null
        windowAlarm.disarm()
        lastSightingCheckMs = null
        seenAdverts.clear()
        classifyCache.clear()
        // No BYE: the transport closes at once (or Bluetooth is already going off), and
        // the remote sees the disconnect through its own GATT callbacks.
        links.keys.toList().forEach { closeLink(it, reason, sendBye = false) }
        clients.values.toList().forEach { it.close() }
        clients.clear()
        pendingByKey.clear()
        server?.close()
        server = null
        scanner = null
        Log.i(TAG, "radio down: $reason")
    }

    private fun nowSecs(): Long = System.currentTimeMillis() / 1000

    /**
     * Reads the node's advert for now into [advertClock] (DESIGN.md §B14.2). False if the node
     * cannot answer: the radio then never comes up with an all-zero token.
     */
    private fun readAdvertState(): Boolean = readAdvert(force = true) != null

    /**
     * DESIGN.md §B14.2: at every window, and whenever the node's contacts version moves (a
     * pairing, a forget, a reset, pairing mode or the relay switch), read the advert state;
     * a new window or token starts a new advertising set (so a new address), a flag change
     * updates the running one.
     */
    private fun refreshAdvertIfDue(force: Boolean = false) {
        if (!radioOn) return
        val action = readAdvert(force) ?: return
        if (!advert.ready) return // the service-added callback starts the set
        val data = advertClock.serviceData ?: return
        when (action) {
            AdvertClock.Action.NEW_SET -> logAdvertising()
            AdvertClock.Action.UPDATE_DATA -> Log.i(TAG, "advert flags now 0x%02x".format(data[1].toInt() and 0xFF))
            AdvertClock.Action.NONE -> Unit
        }
    }

    /** The clock's action for a fresh read, or null when nothing was due or the node could not answer. */
    private fun readAdvert(force: Boolean): AdvertClock.Action? {
        val now = nowSecs()
        if (!force) {
            val version =
                try {
                    node.contactsVersion().toLong()
                } catch (e: Exception) {
                    Log.w(TAG, "contacts version unavailable", e)
                    return null
                }
            if (!advertClock.due(now, version)) return null
        }
        val state =
            try {
                node.advertState(now.toULong())
            } catch (e: Exception) {
                Log.w(TAG, "advert state unavailable", e)
                return null
            }
        ownToken = state.ownToken
        val action =
            advert.onState(
                window = state.window.toLong(),
                serviceData = state.serviceData,
                nextWindowAtSecs = state.nextWindowAt.toLong(),
                version = state.contactsVersion.toLong(),
                readAtSecs = now,
            )
        if (radioOn && action != AdvertClock.Action.NONE) {
            windowAlarm.arm(advertClock.delayToNextWindowMs(System.currentTimeMillis()))
        }
        return action
    }

    /** For the device test: the window and the token's first bytes (public on the air), never the whole token. */
    private fun logAdvertising() {
        Log.i(TAG, "advertising window ${advertClock.window} token ${ServiceData.hexPrefix(ownToken)} (new set)")
    }

    private fun scheduleTick() {
        tick?.cancel()
        tick =
            scheduler.schedule(TICK_MS) {
                tick = null
                if (!radioOn) return@schedule
                onTick()
                scheduleTick()
            }
    }

    private fun onTick() {
        refreshAdvertIfDue()
        refreshLinkKinds()
        enforceRelayCap()
        // A verification that arrived after its link closed.
        verifiedEver.retainAll(peers.peers())
    }

    /** The while-idle backstop: check the clock, then aim at the next window again (never a tight loop). */
    private fun onWindowAlarm() {
        refreshAdvertIfDue()
        if (radioOn) {
            windowAlarm.arm(advertClock.delayToNextWindowMs(System.currentTimeMillis()).coerceAtLeast(ALARM_MIN_MS))
        }
    }

    // ---- discovery -------------------------------------------------------

    /**
     * One `classifyAdvert` per advert per window and contacts version. The version is read live
     * (an atomic load in the node) at every sighting, and the cache is used only while
     * [advertClock] covers now at that version: a removed, forgotten or reset contact, or a
     * window boundary the clock has not caught up with yet, always goes to the node.
     */
    private fun classify(data: ByteArray): AdvertMatch {
        val now = nowSecs()
        val version =
            try {
                node.contactsVersion().toLong()
            } catch (e: Exception) {
                null
            }
        if (version == null || !advertClock.covers(now, version)) return classifyNow(data, now) ?: AdvertMatch.Ignore
        val key = data.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return classifyCache.get(key, advertClock.window, version) { classifyNow(data, now) } ?: AdvertMatch.Ignore
    }

    /** The node's answer, or null if it failed (never cached: the next sighting asks again). */
    private fun classifyNow(
        data: ByteArray,
        now: Long,
    ): AdvertMatch? =
        try {
            when (val m = node.classifyAdvert(data, now.toULong())) {
                is FfiAdvertMatch.Contact -> AdvertMatch.Contact(m.inboxId, m.dialFirst)
                is FfiAdvertMatch.Stranger -> AdvertMatch.Stranger(m.relayOffered, m.dialFirst)
                is FfiAdvertMatch.Pairing -> AdvertMatch.Pairing(m.dialFirst)
                else -> AdvertMatch.Ignore
            }
        } catch (e: Exception) {
            Log.w(TAG, "classifyAdvert failed", e)
            null
        }

    private fun onSighting(
        data: ByteArray,
        device: BluetoothDevice,
        rssi: Int,
    ) {
        if (!radioOn) return
        val now = scheduler.nowMs()
        lastSightingMs = now
        // A BLE event is also a clock check, at most once a second.
        val lastCheck = lastSightingCheckMs
        if (lastCheck == null || now - lastCheck >= SIGHTING_CHECK_MS) {
            lastSightingCheckMs = now
            refreshAdvertIfDue()
        }
        if (ServiceData.isV2(data)) {
            val seen = device.address + ":" + ServiceData.hexPrefix(ServiceData.token(data))
            if (seenAdverts.add(seen)) {
                if (seenAdverts.size > MAX_SIGHTINGS) seenAdverts.remove(seenAdverts.first())
                Log.i(TAG, "saw advert from ${device.address} token ${ServiceData.hexPrefix(ServiceData.token(data))}")
            }
        }
        val match = classify(data)
        val key = planner.sightingKey(match, device.address) ?: return
        pruneSightings(now)
        val sighting = sightings.getOrPut(key) { Sighting(device, now, now) }
        sighting.firstSeenMs = planner.sightingStart(sighting.firstSeenMs, sighting.lastSeenMs, now)
        sighting.device = device
        sighting.lastSeenMs = now
        val dialKey = DialPlanner.dialKey(key, device.address)
        val lost = lastLost[dialKey]
        val dialedKeys = pendingByKey.values.map { it.dialKey } + links.values.mapNotNull { it.dialed?.dialKey }
        val decision =
            planner.decide(
                DialPlanner.Inputs(
                    match = match,
                    waitingSinceMs = maxOf(sighting.firstSeenMs, lost ?: sighting.firstSeenMs),
                    lastLostMs = lost,
                    nowMs = now,
                    relayOn = node.relayEnabled(),
                    busy = planner.isBusy(dialKey, dialedKeys, verified.value.values.map { it.inboxId }),
                    backoffAllows =
                        backoff.canAttempt(dialKey, now) &&
                            contactBackoff.canAttempt(dialKey, now) &&
                            backoff.canAttempt(DialPlanner.DEVICE_PREFIX + device.address, now),
                    openConnections = links.size + pendingByKey.size,
                    relayLinks = relayLinkCount(),
                    evictableRelayKey = oldestRelayKey(),
                ),
            )
        val dial = decision as? DialPlanner.Decision.Dial ?: return
        val conn = GattClientConnection(context, device, handler, gattEvents)
        if (clients.containsKey(conn.key)) return
        dial.evictKey?.let { closeLink(it, "slot for a contact", sendBye = true, hard = true) }
        Log.i(TAG, "dialing ${label(dial.intent)} (rssi $rssi)")
        clients[conn.key] = conn
        pendingByKey[conn.key] = PendingDial(key, dial.intent, device.address)
        conn.connect()
    }

    private fun label(intent: DialPlanner.Intent): String =
        when (intent) {
            is DialPlanner.Intent.Contact -> "a contact"
            DialPlanner.Intent.Relay -> "a relay stranger"
            DialPlanner.Intent.Pairing -> "a pairing phone"
        }

    private fun roleFor(intent: DialPlanner.Intent): FfiLinkRole =
        when (intent) {
            is DialPlanner.Intent.Contact -> FfiLinkRole.DialContact(intent.inboxId)
            DialPlanner.Intent.Relay -> FfiLinkRole.DialRelay
            DialPlanner.Intent.Pairing -> FfiLinkRole.DialPairing
        }

    /**
     * Relay links against the cap: those the node reports as relay, our relay dials whose
     * handshake has not finished yet, and relay dials still connecting.
     */
    private fun relayLinkCount(): Int =
        links.values.count { slot ->
            val kind = linkKinds[slot.key]
            kind == LinkKindTag.RELAY || (kind == null && slot.dialed?.intent == DialPlanner.Intent.Relay)
        } + pendingByKey.values.count { it.intent == DialPlanner.Intent.Relay }

    private fun oldestRelayKey(): String? =
        linkKinds.filterValues { it == LinkKindTag.RELAY }.keys.minByOrNull { links[it]?.readyAtMs ?: Long.MAX_VALUE }

    /** Asks the node each open link's kind (DESIGN.md §B14.3): none while its handshake runs. */
    private fun refreshLinkKinds() {
        for (slot in links.values) {
            val id = slot.peerId ?: continue
            val kind =
                try {
                    node.linkKind(id)
                } catch (e: Exception) {
                    null
                }
            when (kind) {
                FfiLinkKind.CONTACT -> linkKinds[slot.key] = LinkKindTag.CONTACT
                FfiLinkKind.RELAY -> linkKinds[slot.key] = LinkKindTag.RELAY
                FfiLinkKind.PAIRING -> linkKinds[slot.key] = LinkKindTag.PAIRING
                null -> Unit
            }
        }
        linkKinds.keys.retainAll(links.keys)
    }

    /** Strangers that dialed us count against the relay cap too: close the newest beyond it. */
    private fun enforceRelayCap() {
        val relayOldestFirst =
            linkKinds.filterValues { it == LinkKindTag.RELAY }.keys.sortedBy { links[it]?.readyAtMs ?: 0L }
        for (key in planner.relayLinksToClose(relayOldestFirst)) {
            // A stranger that dialed us would redial at once: refuse its address for a while.
            if (links[key]?.role == PeerTable.Role.PERIPHERAL) {
                inboundCooldown.start(key.substringAfter(':'), scheduler.nowMs())
            }
            closeLink(key, "relay slots full", sendBye = true, hard = true)
        }
    }

    private fun pruneSightings(now: Long) {
        // Keyed per device for contacts, so rotating addresses must not grow it without bound.
        if (lastLost.size >= MAX_SIGHTINGS) {
            lastLost.values.removeAll { now - it > SIGHTING_TTL_MS }
            while (lastLost.size >= MAX_SIGHTINGS) lastLost.remove(lastLost.keys.first())
        }
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
                val dialed = pendingByKey.remove(key)
                if (!radioOn) return
                if (role == PeerTable.Role.PERIPHERAL) {
                    val coolingDown = inboundCooldown.active(key.substringAfter(':'), scheduler.nowMs())
                    if (!planner.acceptInbound(links.size + pendingByKey.size, coolingDown)) {
                        val why = if (coolingDown) "cooling down" else "at ${config.maxConnections} connections"
                        Log.i(TAG, "refusing inbound $key: $why")
                        server?.disconnect(key)
                        return
                    }
                }
                val queue =
                    WriteQueue(
                        scheduler,
                        // false = not in flight (stack busy); WriteQueue retries it.
                        submit = { packet -> writeTransport(key, role, packet) },
                        onOverflow = { closeLink(key, "write queue overflow", sendBye = false) },
                    )
                val slot = LinkSlot(key, role, queue, dialed)
                val link =
                    ReliableLink(
                        config =
                            LinkConfig(
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
                val pending = pendingByKey.remove(key)
                if (pending != null) {
                    clients.remove(key)?.close()
                    val delay = backoff.onFailure(pending.dialKey, scheduler.nowMs())
                    Log.i(TAG, "dial failed, status $status (133 = GATT_ERROR); retry in ${delay}ms")
                    return
                }
                val slot = links[key]
                if (slot != null && slot.peerId == null) {
                    slot.dialed?.let { backoff.onFailure(it.dialKey, scheduler.nowMs()) }
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

    /**
     * The accepting side reports Accept here, in the same radio-thread task that sent its
     * link Hello, so the node hears it before the dialer can send its first frame.
     */
    private fun onLinkReady(
        slot: LinkSlot,
        hello: LinkPacket.Hello,
    ) {
        val role =
            when (val ready = LinkOutcome.onReady(slot.role == PeerTable.Role.PERIPHERAL, slot.dialed?.intent)) {
                LinkOutcome.Ready.Accept -> FfiLinkRole.Accept
                is LinkOutcome.Ready.Dial -> roleFor(ready.intent)
                LinkOutcome.Ready.Close -> {
                    closeLink(slot.key, "outbound link without a dial intent", sendBye = true)
                    return
                }
            }
        val peerId = peers.onLinkReady(slot.key)
        slot.peerId = peerId
        slot.readyAtMs = scheduler.nowMs()
        slot.dialed?.let { backoff.onSuccess(it.dialKey) }
        Log.i(TAG, "connection ${slot.key} up as $peerId (${slot.dialed?.let { label(it.intent) } ?: "accepted"})")
        rust("onPeerConnected") { node.onPeerConnected(peerId, role) }
        publishPeers()
        maybeProbeCoded(slot, hello)
        // An inbound stranger over the relay cap closes within seconds, not at the next tick.
        scheduler.schedule(KIND_CHECK_MS) {
            if (links[slot.key] === slot) {
                refreshLinkKinds()
                enforceRelayCap()
            }
        }
    }

    private fun closeLink(
        key: String,
        reason: String,
        sendBye: Boolean,
        hard: Boolean = false,
        transportDelayMs: Long = BYE_FLUSH_MS,
        nodeRequested: Boolean = false,
    ) {
        // Removed before link.close(), so the listener's onClosed does not re-enter.
        val slot = links.remove(key) ?: return
        Log.i(TAG, "link $key (${slot.peerId}) closed: $reason")
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
        val now = scheduler.nowMs()
        val kind = linkKinds.remove(key)
        val lostPeerId = peers.onLinkClosed(key)
        val ever = lostPeerId != null && verifiedEver.remove(lostPeerId)
        val intent = slot.dialed?.intent
        val elsewhere =
            intent is DialPlanner.Intent.Contact &&
                verified.value.values.any { it.inboxId == intent.inboxId && it.peerId != lostPeerId }
        val penalty =
            LinkOutcome.onClose(
                intent = intent,
                everVerified = ever,
                kind = kind,
                nodeRequested = nodeRequested,
                reason = reason,
                wasReady = lostPeerId != null,
                ownPowerDown = !radioOn,
                inboxVerifiedElsewhere = elsewhere,
            )
        applyPenalty(penalty, slot.dialed, key, now)
        if (lostPeerId == null) return
        slot.dialed?.let { lastLost[it.dialKey] = now }
        Log.i(TAG, "connection $lostPeerId lost")
        rust("onPeerLost") { node.onPeerLost(lostPeerId) }
        publishPeers()
    }

    /** A link to this inbox verified: clear its back-offs and last drops on every device. */
    private fun onInboxVerified(contactPrefix: String) {
        contactBackoff.onSuccessWithPrefix(contactPrefix)
        backoff.onSuccessWithPrefix(contactPrefix)
        lastLost.keys.removeAll { it.startsWith(contactPrefix) }
    }

    private fun applyPenalty(
        penalty: LinkOutcome.Penalty,
        dialed: PendingDial?,
        key: String,
        now: Long,
    ) {
        when (penalty) {
            LinkOutcome.Penalty.CONTACT_BACKOFF ->
                dialed?.let {
                    val delay = contactBackoff.onFailure(it.dialKey, now)
                    Log.i(TAG, "contact link $key never verified; backing off ${delay}ms")
                }
            LinkOutcome.Penalty.DEVICE_COOLDOWN -> {
                backoff.penalize(DialPlanner.deviceKey(key), now)
                Log.i(TAG, "cooling down the device of $key")
            }
            LinkOutcome.Penalty.CONTACT_RESET ->
                (dialed?.intent as? DialPlanner.Intent.Contact)?.let {
                    onInboxVerified(DialPlanner.contactBackoffPrefix(it.inboxId))
                }
            LinkOutcome.Penalty.NONE -> Unit
        }
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
        val sightingKey = slot.dialed?.sightingKey ?: return
        if ((codedRejectedUntil[sightingKey] ?: 0L) > scheduler.nowMs()) return
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
                slot.dialed?.let { codedRejectedUntil[it.sightingKey] = scheduler.nowMs() + CODED_RETRY_AFTER_MS }
                Log.i(TAG, "coded PHY rejected for ${slot.peerId}; staying on 1M")
            }
            CodedPhyProbe.Action.None ->
                if (slot.probe?.state == CodedPhyProbe.State.VERIFIED) {
                    Log.i(TAG, "coded PHY verified for ${slot.peerId}")
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
            closeLink(key, "mesh node requested disconnect", sendBye = true, hard = true, nodeRequested = true)
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
        const val TICK_MS = 5_000L
        const val ALARM_MIN_MS = 30_000L
        const val SIGHTING_CHECK_MS = 1_000L
        const val SIGHTING_TTL_MS = 10 * 60 * 1000L
        const val KIND_CHECK_MS = 3_000L
        const val INBOUND_COOLDOWN_MS = 30_000L
    }
}
