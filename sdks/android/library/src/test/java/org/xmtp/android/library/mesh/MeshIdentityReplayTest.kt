package org.xmtp.android.library.mesh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Restore convergence (DESIGN.md §C4.4): the identity replay cache must not leak a stale
 * event across [Mesh.start] attempts, and must be cleared once
 * [org.xmtp.android.library.Client.meshRebaseInstallation] actually fixes the log -- but only
 * then (never on a failed or no-op re-base), and never at the cost of wiping a fresher event that
 * races it. `FfiMeshNode`/`FfiXmtpClient` need the native library and can't be constructed in a
 * plain JVM test (the same limitation [MeshStartKeyOrderTest] and [MeshForegroundServiceStopTest]
 * work around), so this reads the source (comments stripped) and checks the control flow
 * structurally: a linear function body with only an early `return` has only one order events can
 * happen in, so textual order here is execution order. The compare-and-clear logic itself is
 * exercised at runtime in [MeshIdentityEventsTest] -- this file only proves the call sites are
 * wired up in the right order.
 */
class MeshIdentityReplayTest {
    private fun read(path: String) =
        File(path)
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    @Test
    fun a_failed_start_doesnt_leak_a_replayed_event_into_the_next_start() {
        val code = read("src/main/java/org/xmtp/android/library/mesh/Mesh.kt")
        val catchBody =
            Regex("""catch \(e: Exception\) \{(.*?)\}""", RegexOption.DOT_MATCHES_ALL)
                .find(code)
                ?.groupValues
                ?.get(1)
                ?: error("start()'s catch (e: Exception) block not found")
        assertTrue(
            "a failed start must clear the identity replay, or a stale event leaks into the next start",
            Regex("""\bidentity\.clear\(\)""").containsMatchIn(catchBody),
        )
    }

    @Test
    fun meshRebaseInstallation_records_the_generation_before_resolving_and_clears_only_after_applying() {
        // An unconditional clear could wipe a fresh event that
        // races the stale one it means to replace, so the generation must be captured before the
        // re-base even starts, and the clear must be the compare-and-clear overload gated on it.
        // The runtime behaviour of that compare-and-clear is covered directly in
        // MeshIdentityEventsTest (a_successful_rebase_clears_the_resolved_event,
        // a_newer_event_emitted_before_the_clear_survives); this only proves the wiring, which
        // can't run without the native FFI client.
        val body = meshRebaseInstallationBody()
        val recorded = body.indexOf("Mesh.identityEventGeneration()")
        val request = body.indexOf("ffiClient.meshRebaseSignatureRequest()")
        val applied = body.indexOf("ffiApplySignatureRequest(signatureRequest)")
        val clear = body.indexOf("Mesh.clearIdentityEvent(resolvedGeneration)")
        val success = body.lastIndexOf("true")
        assertTrue(
            "meshRebaseInstallation not found or has an unexpected shape",
            recorded >= 0 && request >= 0 && applied >= 0 && success >= 0,
        )
        assertTrue(
            "the generation must be recorded before the re-base starts resolving, not after",
            recorded < request,
        )
        assertTrue(
            "a successful re-base (after applying the signature) must compare-and-clear up to the recorded generation",
            clear in (applied + 1) until success,
        )
    }

    @Test
    fun after_a_failed_rebase_the_event_is_still_replayed() {
        val body = meshRebaseInstallationBody()
        val noopReturn = body.indexOf("return@withContext false")
        val clear = body.indexOf("Mesh.clearIdentityEvent(resolvedGeneration)")
        assertTrue("meshRebaseInstallation not found or has an unexpected shape", noopReturn >= 0 && clear >= 0)
        assertTrue(
            "a no-op re-base (nothing to rebase) must return before any clear, so a real failure never reaches it either",
            noopReturn < clear,
        )
    }

    private fun meshRebaseInstallationBody(): String {
        val code = read("src/main/java/org/xmtp/android/library/Client.kt")
        return Regex(
            """suspend fun `?meshRebaseInstallation`?\(signingKey: SigningKey\): Boolean =(.*?)\n    @DelicateApi""",
            RegexOption.DOT_MATCHES_ALL,
        ).find(code)?.groupValues?.get(1) ?: error("Client.meshRebaseInstallation not found")
    }
}
