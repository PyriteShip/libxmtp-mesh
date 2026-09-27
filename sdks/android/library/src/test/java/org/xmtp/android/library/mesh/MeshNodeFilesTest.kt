package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class MeshNodeFilesTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val inboxA = "a".repeat(64)
    private val inboxB = "b".repeat(64)

    private fun files(inboxId: String = inboxA) = MeshNodeFiles(tmp.root, inboxId)

    private fun node(
        inboxId: String,
        generation: Long,
    ) = "xmtp-mesh-node-$inboxId-$generation.db3"

    @Test
    fun starts_at_generation_zero() {
        assertEquals(node(inboxA, 0), files().current().name)
    }

    /** A new installation must never reopen the previous one's node DB. */
    @Test
    fun rotate_moves_to_a_fresh_file_and_deletes_older_generations() {
        val files = files()
        val old = files.current().apply { writeText("node") }
        val wal = File(tmp.root, old.name + "-wal").apply { writeText("wal") }
        val client = MeshNodeFiles.libxmtpDbFile(tmp.root, inboxA).apply { writeText("client db") }
        val next = files.rotate()
        assertEquals(node(inboxA, 1), next.name)
        assertEquals(next, files.current())
        assertFalse(old.exists())
        assertFalse(wal.exists())
        assertTrue("the libxmtp client DB is not ours to delete", client.exists())
    }

    @Test
    fun the_generation_survives_a_new_instance() {
        files().rotate()
        assertEquals(node(inboxA, 1), files().current().name)
    }

    @Test
    fun generation_10_is_not_mistaken_for_generation_1() {
        File(tmp.root, MeshNodeFiles.pointerName(inboxA)).writeText("0")
        val ten = File(tmp.root, node(inboxA, 10)).apply { writeText("stale") }
        val next = files().rotate()
        assertEquals(node(inboxA, 1), next.name)
        assertFalse(ten.exists())
    }

    /** A torn/corrupt pointer must not orphan a real node database (DESIGN.md §B10.1). */
    @Test
    fun a_corrupt_pointer_recovers_the_highest_existing_generation() {
        File(tmp.root, MeshNodeFiles.pointerName(inboxA)).writeText("not a number")
        File(tmp.root, node(inboxA, 1)).writeText("gen1")
        File(tmp.root, node(inboxA, 2)).writeText("gen2")
        assertEquals(node(inboxA, 2), files().current().name)
    }

    @Test
    fun a_corrupt_pointer_with_no_files_reads_as_generation_zero() {
        File(tmp.root, MeshNodeFiles.pointerName(inboxA)).writeText("not a number")
        assertEquals(node(inboxA, 0), files().current().name)
    }

    @Test
    fun a_missing_pointer_with_files_present_recovers() {
        File(tmp.root, node(inboxA, 3)).writeText("gen3")
        assertEquals(node(inboxA, 3), files().current().name)
    }

    @Test
    fun a_leftover_temp_file_does_not_confuse_generation() {
        File(tmp.root, MeshNodeFiles.pointerName(inboxA)).writeText("not a number")
        File(tmp.root, node(inboxA, 1)).writeText("gen1")
        // Mimics a temp file left behind by a writePointer() that died before its rename.
        File(tmp.root, "${MeshNodeFiles.pointerName(inboxA)}.9999999999999999999.tmp").writeText("5")
        assertEquals(node(inboxA, 1), files().current().name)
    }

    // ---- D20: one node per inbox, following the libxmtp DB ----

    @Test
    fun two_inboxes_stay_independent() {
        val a = files(inboxA)
        val b = files(inboxB)
        val aNode = a.rotate().apply { writeText("a") }
        val bNode = b.current().apply { writeText("b") }
        b.rotate()
        b.rotate()
        assertEquals(node(inboxB, 2), b.current().name)
        assertEquals("rotating B leaves A's generation alone", node(inboxA, 1), a.current().name)
        assertTrue("rotating B never deletes A's node", aNode.exists())
        assertFalse(bNode.exists())
        a.rotate()
        assertEquals("rotating A leaves B's generation alone", node(inboxB, 2), b.current().name)
    }

    @Test
    fun an_inbox_without_a_libxmtp_db_rotates_to_a_fresh_node() {
        val files = files()
        val old = files.current().apply { writeText("bound to the deleted installation") }
        val next = files.forClient(MeshNodeFiles.libxmtpDbFile(tmp.root, inboxA))
        assertEquals(node(inboxA, 1), next.name)
        assertFalse(old.exists())
    }

    @Test
    fun an_inbox_with_a_libxmtp_db_keeps_its_generation() {
        val files = files()
        files.rotate()
        files.rotate()
        val current = files.current().apply { writeText("bound to the kept installation") }
        val libxmtp = MeshNodeFiles.libxmtpDbFile(tmp.root, inboxA).apply { writeText("kept libxmtp db") }
        assertEquals(current, files.forClient(libxmtp))
        assertEquals(node(inboxA, 2), files.current().name)
        assertTrue(current.exists())
    }

    @Test
    fun the_libxmtp_db_name_matches_client_kt() {
        // Client.createFfiClient: "xmtp-${options.api.env}-$inboxId.db3"; MESH prints as "MESH".
        assertEquals("xmtp-MESH-$inboxA.db3", MeshNodeFiles.libxmtpDbFile(tmp.root, inboxA).name)
    }

    @Test
    fun rotate_all_rotates_every_inbox_and_nothing_else() {
        val aOld = files(inboxA).current().apply { writeText("a") }
        files(inboxB).rotate()
        val bOld = files(inboxB).current().apply { writeText("b") }
        val libxmtp = MeshNodeFiles.libxmtpDbFile(tmp.root, inboxA).apply { writeText("client db") }
        MeshNodeFiles.rotateAll(tmp.root)
        assertEquals(node(inboxA, 1), files(inboxA).current().name)
        assertEquals(node(inboxB, 2), files(inboxB).current().name)
        assertFalse(aOld.exists())
        assertFalse(bOld.exists())
        assertTrue(libxmtp.exists())
    }

    @Test
    fun a_legacy_device_wide_node_is_neither_an_inbox_nor_a_generation() {
        File(tmp.root, "xmtp-mesh-node-7.db3").writeText("mesh.2 layout")
        File(tmp.root, "xmtp-mesh-node.generation").writeText("7")
        assertEquals(node(inboxA, 0), files().current().name)
        MeshNodeFiles.rotateAll(tmp.root) // must not throw on, or adopt, the legacy names
        assertEquals(node(inboxA, 0), files().current().name)
    }

    @Test(expected = IllegalArgumentException::class)
    fun an_inbox_id_that_could_alias_a_file_name_is_refused() {
        MeshNodeFiles(tmp.root, "../x")
    }
}
