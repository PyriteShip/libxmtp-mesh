package org.xmtp.android.library.mesh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import uniffi.xmtpv3.FfiMeshIdentityCallback
import uniffi.xmtpv3.FfiMeshResyncOutcome

/** What the client did after its mesh node replaced an inbox's identity log (restore convergence). */
enum class MeshIdentityOutcome {
    /** The winning log was reloaded; nothing to do. */
    RELOADED,

    /** This installation is not in its inbox's winning log: call [org.xmtp.android.library.Client.meshRebaseInstallation]. */
    REBASE_NEEDED,

    /** The winning log is full; no re-base is possible. Show "Too many devices on this identity". */
    TOO_MANY_INSTALLATIONS,
}

data class MeshIdentityEvent(
    val inboxId: String,
    val outcome: MeshIdentityOutcome,
)

/** In the error a re-base fails with when the winning log is full (Rust `MESH_TOO_MANY_INSTALLATIONS`). */
const val MESH_TOO_MANY_INSTALLATIONS = "mesh: too many installations"

/** True when this exception, or any cause, is a re-base refused because the winning log is full. */
fun Throwable.isMeshTooManyInstallations(): Boolean =
    generateSequence(this) { it.cause }.any { it.message?.contains(MESH_TOO_MANY_INSTALLATIONS) == true }

/**
 * Bridges the node's identity resyncs (`FfiMeshNode.streamIdentity`) to [events]. The latest event
 * is replayed to a late collector: the React Native bridge starts collecting just after [Mesh.start],
 * and an app that missed it still sees it. [clear] forgets it outright, e.g. when the radio stops
 * or a start fails; [clearIfUnresolved] is the compare-and-clear a resolved re-base uses instead,
 * so a fresher event that races it survives rather than being wiped along with
 * the stale one. Called on a tokio thread; never blocks (the critical sections below are
 * in-process and uncontended in practice, not I/O, same as `MutableSharedFlow.tryEmit`'s own
 * internal synchronization).
 */
class MeshIdentityEvents : FfiMeshIdentityCallback {
    private val flow = MutableSharedFlow<MeshIdentityEvent>(replay = 1, extraBufferCapacity = 16)
    private val lock = Any()

    // Bumped under [lock] with every emitted event. clearIfUnresolved compares against a snapshot
    // taken before this moved on, telling "still the stale event I meant to clear" apart from "a
    // fresh one already landed" (compare-and-clear).
    private var generation = 0L

    val events: SharedFlow<MeshIdentityEvent> = flow.asSharedFlow()

    override fun onIdentityResynced(
        inboxId: String,
        outcome: FfiMeshResyncOutcome,
    ) {
        synchronized(lock) {
            generation++
            flow.tryEmit(MeshIdentityEvent(inboxId, outcome.toMeshOutcome()))
        }
    }

    /** The generation of the latest emitted event (0 before any). Record this before resolving one. */
    fun generation(): Long = synchronized(lock) { generation }

    /**
     * Unconditional: forgets the latest replayed event outright. For a resolved re-base, use
     * [clearIfUnresolved] instead -- this one has no way to spare a fresher, concurrently-arrived
     * event.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    fun clear() = flow.resetReplayCache()

    /**
     * Clears the latest replayed event only if [resolvedGeneration] is still current -- i.e. no
     * newer event has been emitted since it was recorded. Atomic with every emit under [lock], so
     * an event that lands concurrently with this call is never wiped by a clear meant for an
     * older one (compare-and-clear). Returns whether it cleared.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    fun clearIfUnresolved(resolvedGeneration: Long): Boolean =
        synchronized(lock) {
            if (generation <= resolvedGeneration) {
                flow.resetReplayCache()
                true
            } else {
                false
            }
        }
}

internal fun FfiMeshResyncOutcome.toMeshOutcome(): MeshIdentityOutcome =
    when (this) {
        FfiMeshResyncOutcome.RELOADED -> MeshIdentityOutcome.RELOADED
        FfiMeshResyncOutcome.REBASE_NEEDED -> MeshIdentityOutcome.REBASE_NEEDED
        FfiMeshResyncOutcome.TOO_MANY_INSTALLATIONS -> MeshIdentityOutcome.TOO_MANY_INSTALLATIONS
    }
