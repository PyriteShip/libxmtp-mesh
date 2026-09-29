package org.xmtp.android.library.mesh

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.xmtp.android.library.Client
import uniffi.xmtpv3.FfiContact
import uniffi.xmtpv3.FfiMeshIdentityStream
import uniffi.xmtpv3.FfiMeshNode
import uniffi.xmtpv3.FfiMeshStats
import uniffi.xmtpv3.FfiPairingRefusal
import uniffi.xmtpv3.FfiPendingPairing
import uniffi.xmtpv3.FfiRelayStats
import uniffi.xmtpv3.FfiXmtpClient
import uniffi.xmtpv3.openMeshNode

/** Pairing as the app shows it (DESIGN.md §B14.4). */
data class MeshPairingState(
    /** The node is in pairing mode (it leaves by itself after a pairing or 5 unfinished ones). */
    val on: Boolean,
    /** Open pairings and the 6-digit code each shows. */
    val pending: List<FfiPendingPairing>,
    /**
     * Pairings refused because the other phone's link key is already on file for another
     * contact. Each names two people: the person being paired now ([FfiPairingRefusal.peerId],
     * with the [FfiPairingRefusal.code] they compared) and the contact on file
     * ([FfiPairingRefusal.conflictingInboxId]). Either one may be the impostor: show both and
     * ask the user which person they trust. Never assume the contact on file is the impostor;
     * [Mesh.forgetContact] frees the key only when the user chooses the new person.
     */
    val refusals: List<FfiPairingRefusal>,
    /** Times this node left pairing mode after too many unfinished pairings. */
    val attemptsExhausted: ULong,
)

/**
 * Entry point for apps: start the BLE radio for a client created with
 * `ClientOptions.Api(env = XMTPEnvironment.MESH, mesh = options)`.
 * Call from the foreground (Android 12+ restricts starting foreground services
 * from the background). Runtime permissions: [org.xmtp.android.library.mesh.policy.MeshPermissions.requested].
 * Presence for the UI: [MeshRadio.verifiedPeers] on [radio]. Before creating a DM with a
 * nearby contact, wait for a verified peer **and** [Client.meshCanMessage] on its
 * installation id (see [MeshRadio.verifiedPeers]).
 * Bluetooth off is not an error: [start] succeeds, [MeshRadio.radioUp] stays false (show
 * "Bluetooth is off" from it), and the radio comes up when Bluetooth turns on.
 */
object Mesh {
    private const val TAG = "Mesh"
    private val lock = Mutex()

    // MeshRadio holds only the application context, which lives as long as the process.
    @SuppressLint("StaticFieldLeak")
    @Volatile
    var radio: MeshRadio? = null
        private set

    // Read without the lock by relayStats(), stats() and the contacts/pairing calls.
    @Volatile
    private var node: FfiMeshNode? = null
    private var relayClient: FfiXmtpClient? = null
    private var battery: MeshBatteryWatch? = null

    // A SupervisorJob keeps one onBattery failure from cancelling the scope, but that alone
    // still lets an uncaught exception crash the process; this handler catches and logs it.
    private val relayExceptionHandler =
        CoroutineExceptionHandler { _, e -> Log.w(TAG, "relay battery watch failed", e) }
    private val relayScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + relayExceptionHandler)

    /** The relay switch and what the node is doing (DESIGN.md §R8). */
    val relay: StateFlow<MeshRelayState> get() = MeshRelayControl.relay
    private var identityStream: FfiMeshIdentityStream? = null
    private val identity = MeshIdentityEvents()

    /**
     * Identity resyncs of the running node (restore convergence). The latest is replayed.
     * [MeshIdentityOutcome.REBASE_NEEDED]: call [Client.meshRebaseInstallation] with the wallet's
     * signer, then revoke the other installations (DESIGN.md D28).
     */
    val identityEvents: SharedFlow<MeshIdentityEvent> get() = identity.events

    /**
     * The identity replay's current generation (compare-and-clear): record this
     * ([Client.meshRebaseInstallation] does, at the very start, before anything else) and pass it
     * back to [clearIdentityEvent] so the clear is skipped if a newer event has landed meanwhile.
     */
    internal fun identityEventGeneration(): Long = identity.generation()

    /**
     * Clears the latest replayed identity event, but only if it's still the one current when
     * [resolvedGeneration] was recorded (compare-and-clear: an unconditional clear
     * could wipe a fresh event racing the stale one it means to replace). Call once
     * [Client.meshRebaseInstallation] actually applies a re-base, so a late collector doesn't keep
     * seeing a stale [MeshIdentityOutcome.REBASE_NEEDED] or
     * [MeshIdentityOutcome.TOO_MANY_INSTALLATIONS] for an inbox that's already fixed. Do not call
     * this for a failed or no-op re-base. Returns whether it cleared.
     */
    internal fun clearIdentityEvent(resolvedGeneration: Long): Boolean = identity.clearIfUnresolved(resolvedGeneration)

    /**
     * True while the foreground service holds foreground status. After [start] it can stay
     * false when the platform refused; tell the user that background
     * delivery is off.
     */
    val foreground: StateFlow<Boolean> get() = MeshForeground.active

    /**
     * Opens the mesh node, starts sync and the radio, and returns the running radio (the
     * same one if already started). Pair every start with [stop] (e.g. on logout or account
     * switch): the node, client and radio reference each other across the Rust/Kotlin
     * boundary (node → sync → client and transport → radio → node), and only [stop]
     * (`FfiMeshNode.stopSync`) breaks that cycle. Without it the node, the client, the
     * radio thread and the GATT server stay alive for the life of the process.
     *
     * If the mesh is already running, this returns the running [radio] as-is and `relay` is
     * ignored (the node keeps whatever relay state it already has); use [setRelayEnabled] to
     * change it.
     *
     * `relay`: the user's relay choice, defaulting to the last recorded choice
     * ([MeshRelayControl.current]'s `userEnabled`), whose own initial value is on — so "on by
     * default" holds for a first start. The node relays when it is on and battery is not below
     * 15% (resuming at 20% or when charging).
     *
     * `accountKey`: the account's 32-byte secp256k1 private key (the key the recovery phrase
     * restores); wiped before this returns. `beginRestoreWindow`: true on the first start after
     * a restore from the recovery phrase or a local-data reset (DESIGN.md §B14.7).
     */
    suspend fun start(
        context: Context,
        client: Client,
        options: MeshOptions,
        accountKey: ByteArray,
        config: MeshRadioConfig = MeshRadioConfig(),
        relay: Boolean = MeshRelayControl.current().userEnabled,
        beginRestoreWindow: Boolean = false,
    ): MeshRadio =
        // The wipe encloses the lock too: a caller cancelled while waiting for it still wipes.
        try {
            lock.withLock {
                radio?.let { return@withLock it }
                withContext(Dispatchers.IO) {
                    val app = context.applicationContext
                    options.ensureParentDir()
                    MeshLegacyPrefs.clear(app)
                    val n = openMeshNode(options.dbPath, options.encryptionKey)
                    val r = MeshRadio(app, n, config)
                    try {
                        // Suspends into uniffi's tokio runtime, which the node keeps for its sessions.
                        // Subscribe before start_sync, whose identity task replays
                        // pending resyncs at once; a RebaseNeeded sent before this would be lost.
                        identityStream = n.streamIdentity(identity)
                        // DESIGN.md §B14.1: the link keys come from the account key; start_sync
                        // refuses without them. The node keeps only derived keys.
                        n.setAccountKey(accountKey)
                        // §B14.7: a phone restored from its recovery phrase (or with its local
                        // data reset) lets its contacts back in for 72 hours.
                        if (beginRestoreWindow) n.beginRestoreWindow()
                        n.startSync(client.ffiClientForMesh, r)
                        // DESIGN.md §R8: decide before the radio's links come up, so
                        // every session advertises the right relay flag in Hello.
                        val watch = MeshBatteryWatch(app) { p, ch -> relayScope.launch { onBattery(p, ch) } }
                        val (percent, charging) = watch.readNow()
                        val paused = MeshRelayPolicy.pausedForBattery(false, percent, charging)
                        applyRelay(n, client.ffiClientForMesh, userEnabled = relay, pausedForBattery = paused)
                        r.start()
                        watch.start()
                        battery = watch
                        relayClient = client.ffiClientForMesh
                        // Inside the try: if the platform refuses the foreground service, undo the start.
                        MeshForegroundService.start(app)
                    } catch (e: Exception) {
                        battery?.stop()
                        battery = null
                        relayClient = null
                        identityStream?.end()
                        identityStream = null
                        // A stale event from this failed attempt must not leak
                        // into a later, possibly different-inbox, start.
                        identity.clear()
                        n.stopSync()
                        r.stop()
                        // A failed start must not leave the published state claiming the relay is
                        // active on a node that no longer exists.
                        MeshRelayControl.update(
                            MeshRelayControl.current().userEnabled,
                            pausedForBattery = false,
                            active = false,
                        )
                        throw e
                    }
                    node = n
                    radio = r
                    r
                }
            }
        } finally {
            accountKey.fill(0)
        }

    /**
     * Stops sync (breaking the Rust/Kotlin reference cycle described on [start]), the radio
     * and the foreground service. Required on logout; safe to call when not started.
     */
    suspend fun stop(context: Context) =
        lock.withLock {
            node?.stopSync() // cancels sessions and clears presence before the radio goes away
            battery?.stop()
            battery = null
            relayClient = null
            MeshRelayControl.update(MeshRelayControl.current().userEnabled, pausedForBattery = false, active = false)
            identityStream?.end()
            identityStream = null
            identity.clear()
            radio?.stop()
            node = null
            radio = null
            MeshForegroundService.stop(context.applicationContext)
        }

    /**
     * The user's relay choice (Settings). Applies at once to a running node, with no restart:
     * the Rust engine re-links live sessions. While stopped it is only recorded (in
     * [MeshRelayControl]); the next [start] picks it up on its own through `relay`'s default.
     */
    suspend fun setRelayEnabled(enabled: Boolean) =
        lock.withLock {
            val s = MeshRelayControl.current()
            val n = node
            val c = relayClient
            if (n == null || c == null) {
                MeshRelayControl.update(enabled, s.pausedForBattery, active = false)
            } else {
                withContext(Dispatchers.IO) { applyRelay(n, c, enabled, s.pausedForBattery) }
            }
        }

    /** Relay counters of the running node, or null when stopped. */
    fun relayStats(): FfiRelayStats? = node?.relayStats()

    /**
     * Signed-sequencing counters of the running node (DESIGN.md §B13): rows this node signed
     * and checked, rows refused by reason, conflicting copies kept as proof, and peers refused
     * for an older protocol version. Counted since the node was opened, so they start at zero
     * on every [start]. Null when stopped.
     */
    fun stats(): FfiMeshStats? = node?.meshStats()

    /**
     * The message of the [MeshException] thrown by calls that need a running node. Those calls
     * also throw `uniffi.xmtpv3.FfiException` when the node refuses (for example a store
     * error); callers can treat both alike. A call racing [stop] may still reach the node as it
     * stops; it then gets the node's answer (possibly an `FfiException`) instead of this.
     */
    const val NOT_RUNNING = "the mesh is not running"

    private fun running(): FfiMeshNode = node ?: throw MeshException(NOT_RUNNING)

    /**
     * Pairing mode (DESIGN.md §B14.4): advertise the pairing flag and accept pairing links. Show
     * a countdown and turn it off when the pairing screen closes; the node also leaves it by
     * itself after a pairing or after 5 unfinished ones. A no-op while stopped (a new start
     * begins with pairing mode off).
     */
    fun setPairingMode(on: Boolean) {
        val n = node ?: return
        n.setPairingMode(on)
        // Fast path; the radio's contacts-version check is the backstop.
        radio?.refreshAdvert()
    }

    /**
     * Null while stopped. Poll it while the pairing screen is open (there is no event). Not an
     * atomic snapshot: its fields are read one after another, so a pairing may move between
     * them; the next poll catches up.
     */
    fun pairingState(): MeshPairingState? {
        val n = node ?: return null
        return MeshPairingState(
            on = n.pairingMode(),
            pending = n.pendingPairings(),
            refusals = n.pairingRefusals(),
            attemptsExhausted = n.meshStats().pairingAttemptsExhausted,
        )
    }

    /** The person compared the codes and they match. */
    fun confirmPairing(peerId: String) = running().confirmPairing(peerId)

    /** The codes differ, or the person declined. */
    fun rejectPairing(peerId: String) = running().rejectPairing(peerId)

    /**
     * Live contacts; `autoAdded` ones came back by themselves during a restore window (list them
     * for [confirmRestoredContact] or [removeContact]). Null while stopped. Throws
     * `uniffi.xmtpv3.FfiException` if the node's store cannot be read.
     */
    fun contacts(): List<FfiContact>? = node?.contacts()

    /**
     * Stop recognising and accepting this contact, and close its links. Offer
     * [resetDiscoveryKey] next, so the removed contact stops recognising this phone too.
     */
    fun removeContact(inboxId: String): Boolean = running().removeContact(inboxId).also { radio?.refreshAdvert() }

    /**
     * Remove and forget completely, so a key this contact claimed is free again (the answer to a
     * pairing refusal when the user trusts the new person). Offer [resetDiscoveryKey] next.
     */
    fun forgetContact(inboxId: String): Boolean = running().forgetContact(inboxId).also { radio?.refreshAdvert() }

    /**
     * Advertise under a new discovery key, so removed contacts stop recognising this phone.
     * Returns the new generation.
     */
    fun resetDiscoveryKey(): UInt = running().resetDiscoveryKey().also { radio?.refreshAdvert() }

    /** The end (unix seconds) of the open restore window (DESIGN.md §B14.7), or null (also while stopped). */
    fun restoreWindowUntil(): ULong? = node?.restoreWindowUntil()

    /** Close the restore window now (the user is done reconnecting). */
    fun endRestoreWindow() = running().endRestoreWindow()

    /**
     * The user keeps a contact the restore window added: it gets this phone's card from now on.
     * Returns whether such a contact was waiting.
     */
    fun confirmRestoredContact(inboxId: String): Boolean = running().confirmRestoredContact(inboxId)

    private suspend fun onBattery(
        percent: Int,
        charging: Boolean,
    ) = lock.withLock {
        val n = node ?: return@withLock
        val c = relayClient ?: return@withLock
        val s = MeshRelayControl.current()
        val paused = MeshRelayPolicy.pausedForBattery(s.pausedForBattery, percent, charging)
        if (paused != s.pausedForBattery) applyRelay(n, c, s.userEnabled, paused)
    }

    /** Call with [lock] held. Brings the node in line with (userEnabled && !pausedForBattery). */
    private fun applyRelay(
        n: FfiMeshNode,
        client: FfiXmtpClient,
        userEnabled: Boolean,
        pausedForBattery: Boolean,
    ) {
        val want = userEnabled && !pausedForBattery
        val on = n.relayEnabled()
        if (want && !on) n.enableRelay(client)
        if (!want && on) n.disableRelay()
        MeshRelayControl.update(userEnabled, pausedForBattery, active = n.relayEnabled())
        // The advert's relay flag (DESIGN.md §B14.2). On the first start this runs before
        // [radio] is set; the radio's power-up read covers that.
        radio?.refreshAdvert()
    }
}
