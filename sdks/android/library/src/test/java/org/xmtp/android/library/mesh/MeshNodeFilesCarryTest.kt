package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * Reset carry (DESIGN.md §B10.2, D21):
 * a rotation that follows the libxmtp DB carries the inbox's identity log from the retiring
 * generation into the next one. A reset rotates twice (stopAndRotate, then forClient because the
 * libxmtp DB is gone), so each rotation must carry. The Rust carry itself is tested in
 * bindings/mobile (carry_mesh_identity_log); here a fake stands in for it. Robolectric: rotate
 * logs through android.util.Log.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MeshNodeFilesCarryTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val inboxA = "a".repeat(64)

    private fun files() = MeshNodeFiles(tmp.root, inboxA)

    private fun node(generation: Long) = File(tmp.root, "xmtp-mesh-node-$inboxA-$generation.db3")

    private fun sidecar(
        node: File,
        suffix: String,
    ) = File(node.path + suffix)

    /** Stands in for the Rust carry: appends the source's text to the target, records the call. */
    private class FakeCarrier(
        private val fail: Boolean = false,
    ) : IdentityLogCarrier {
        val calls = mutableListOf<Triple<String, String, String>>()

        override fun carry(
            from: File,
            to: File,
            inboxId: String,
        ) {
            calls += Triple(from.name, to.name, inboxId)
            to.appendText(from.readText())
            if (fail) {
                File(to.path + "-wal").writeText("partial")
                throw IllegalStateException("carry failed")
            }
        }
    }

    @Test
    fun rotate_carries_the_log_into_the_next_generation_and_deletes_the_old_one() {
        node(0).writeText("log")
        val carrier = FakeCarrier()
        val next = files().rotate(carrier)
        assertEquals(node(1), next)
        assertEquals("log", next.readText())
        assertFalse(node(0).exists())
        assertEquals(listOf(Triple(node(0).name, node(1).name, inboxA)), carrier.calls)
    }

    /** The reset path: stopAndRotate, then forClient (the libxmtp DB is gone). */
    @Test
    fun the_double_rotation_of_a_reset_keeps_the_log() {
        node(0).writeText("log")
        val carrier = FakeCarrier()
        val files = files()
        files.rotate(carrier)
        val forClient = files.forClient(MeshNodeFiles.libxmtpDbFile(tmp.root, inboxA), carrier)
        assertEquals(node(2), forClient)
        assertEquals("log", forClient.readText())
        assertFalse(node(0).exists())
        assertFalse(node(1).exists())
        assertEquals(2, carrier.calls.size)
    }

    @Test
    fun forClient_with_a_libxmtp_db_neither_rotates_nor_carries() {
        node(0).writeText("log")
        val libxmtp = MeshNodeFiles.libxmtpDbFile(tmp.root, inboxA).apply { writeText("kept") }
        val carrier = FakeCarrier()
        assertEquals(node(0), files().forClient(libxmtp, carrier))
        assertTrue(carrier.calls.isEmpty())
    }

    /** A brand-new inbox has nothing to carry; no file may be created for it. */
    @Test
    fun nothing_to_carry_when_the_current_generation_has_no_file() {
        val carrier = FakeCarrier()
        val next = files().rotate(carrier)
        assertEquals(node(1), next)
        assertFalse(next.exists())
        assertTrue(carrier.calls.isEmpty())
    }

    /** A failed carry must not leave a partial log (it would fork at N+1). */
    @Test
    fun a_failed_carry_still_rotates_to_an_empty_node() {
        node(0).writeText("log")
        val next = files().rotate(FakeCarrier(fail = true))
        assertEquals(node(1), next)
        assertFalse("a partial carry must not survive", next.exists())
        assertFalse(sidecar(next, "-wal").exists())
        assertFalse(node(0).exists())
    }

    /** Pointer missing, so generation() would otherwise pick the highest file. */
    @Test
    fun during_a_carry_the_partial_next_file_is_never_current() {
        node(0).writeText("log")
        var currentDuringCarry: File? = null
        val carrier =
            IdentityLogCarrier { _, to, _ ->
                to.writeText("part")
                currentDuringCarry = files().current() // what a restarted process would read now
                throw IllegalStateException("process died")
            }
        files().rotate(carrier)
        assertEquals(node(0), currentDuringCarry)
    }

    /** A process death mid-carry left gen 1; the retry must replace it. */
    @Test
    fun a_leftover_next_generation_from_an_interrupted_carry_is_replaced() {
        File(tmp.root, MeshNodeFiles.pointerName(inboxA)).writeText("0")
        node(0).writeText("log")
        node(1).writeText("partial ")
        sidecar(node(1), "-wal").writeText("stale wal")
        val next = files().rotate(FakeCarrier())
        assertEquals("log", next.readText())
        assertFalse(sidecar(node(1), "-wal").exists())
    }
}
