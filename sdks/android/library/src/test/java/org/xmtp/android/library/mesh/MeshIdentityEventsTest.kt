package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.xmtpv3.FfiMeshResyncOutcome

/**
 * Restore convergence (DESIGN.md §C4.4): the node's identity resyncs reach the app as a flow.
 * The Rust stream is tested in
 * bindings/mobile; here the callback is driven directly.
 */
class MeshIdentityEventsTest {
    @Test
    fun the_latest_outcome_is_replayed_to_a_late_collector() {
        val events = MeshIdentityEvents()
        events.onIdentityResynced("inbox-a", FfiMeshResyncOutcome.RELOADED)
        events.onIdentityResynced("inbox-b", FfiMeshResyncOutcome.REBASE_NEEDED)
        assertEquals(
            listOf(MeshIdentityEvent("inbox-b", MeshIdentityOutcome.REBASE_NEEDED)),
            events.events.replayCache,
        )
    }

    @Test
    fun every_outcome_maps() {
        val events = MeshIdentityEvents()
        events.onIdentityResynced("i", FfiMeshResyncOutcome.TOO_MANY_INSTALLATIONS)
        assertEquals(
            MeshIdentityOutcome.TOO_MANY_INSTALLATIONS,
            events.events.replayCache
                .single()
                .outcome,
        )
        events.onIdentityResynced("i", FfiMeshResyncOutcome.RELOADED)
        assertEquals(
            MeshIdentityOutcome.RELOADED,
            events.events.replayCache
                .single()
                .outcome,
        )
    }

    @Test
    fun clear_forgets_the_last_outcome_when_the_radio_stops() {
        val events = MeshIdentityEvents()
        events.onIdentityResynced("i", FfiMeshResyncOutcome.REBASE_NEEDED)
        events.clear()
        assertTrue(events.events.replayCache.isEmpty())
    }

    @Test
    fun the_too_many_installations_marker_is_found_in_any_cause() {
        val ffi = RuntimeException("[GenericError::Generic] mesh: too many installations: the inbox already has 10/10")
        assertTrue(IllegalStateException("wrapped", ffi).isMeshTooManyInstallations())
        assertFalse(RuntimeException("mesh: something else").isMeshTooManyInstallations())
    }

    // clearIdentityEvent()'s unconditional
    // resetReplayCache() could wipe a fresh event that races the stale one it meant to clear.
    // MeshIdentityEvents.clearIfUnresolved is the fix: a compare-and-clear gated on a generation
    // counter recorded before the re-base started resolving.

    @Test
    fun a_failed_start_leaves_no_replay() {
        // Mesh.start's catch block clears the replay this same way (identity.clear(), an
        // unconditional teardown, not the compare-and-clear below) on any exception between
        // streamIdentity and success, so a stale event never leaks into the next start.
        val events = MeshIdentityEvents()
        events.onIdentityResynced("i", FfiMeshResyncOutcome.TOO_MANY_INSTALLATIONS)
        events.clear()
        assertTrue(events.events.replayCache.isEmpty())
    }

    @Test
    fun a_successful_rebase_clears_the_resolved_event() {
        val events = MeshIdentityEvents()
        events.onIdentityResynced("i", FfiMeshResyncOutcome.REBASE_NEEDED)
        val resolvedGeneration = events.generation() // recorded when the re-base started resolving
        assertTrue(events.clearIfUnresolved(resolvedGeneration))
        assertTrue(events.events.replayCache.isEmpty())
    }

    @Test
    fun a_newer_event_emitted_before_the_clear_survives() {
        val events = MeshIdentityEvents()
        events.onIdentityResynced("i", FfiMeshResyncOutcome.REBASE_NEEDED)
        val resolvedGeneration = events.generation() // the re-base recorded this...
        events.onIdentityResynced("i", FfiMeshResyncOutcome.TOO_MANY_INSTALLATIONS) // ...then a fresh event landed
        assertFalse(events.clearIfUnresolved(resolvedGeneration))
        assertEquals(
            listOf(MeshIdentityEvent("i", MeshIdentityOutcome.TOO_MANY_INSTALLATIONS)),
            events.events.replayCache,
        )
    }

    @Test
    fun a_failed_rebase_keeps_the_event() {
        // A failed or no-op re-base never calls clearIfUnresolved at all (Client.kt returns or
        // throws before reaching it), so the event is simply left exactly as it was.
        val events = MeshIdentityEvents()
        events.onIdentityResynced("i", FfiMeshResyncOutcome.REBASE_NEEDED)
        assertEquals(
            listOf(MeshIdentityEvent("i", MeshIdentityOutcome.REBASE_NEEDED)),
            events.events.replayCache,
        )
    }
}
