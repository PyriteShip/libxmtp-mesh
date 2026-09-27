package org.xmtp.android.library.mesh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * D22: [MeshNodeFiles.rotate] must remove the short-id entry of the generation it retires,
 * so no stale ids are left behind, and the node's new generation gets a fresh id.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MeshNodeFilesShortIdTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val inboxA = "a".repeat(64)
    private val inboxB = "b".repeat(64)

    private fun prefsHas(nodeKey: String): Boolean =
        context.getSharedPreferences("org.xmtp.android.mesh", Context.MODE_PRIVATE).contains("short_id.$nodeKey")

    @Test
    fun rotate_forgets_the_retired_generation_short_id_and_the_new_generation_gets_a_fresh_one() {
        val files = MeshNodeFiles(tmp.root, inboxA, context)
        val oldKey = files.current().name
        // rotate() only forgets generations it actually finds on disk (matches the existing
        // MeshNodeFilesTest pattern of writing the old file before rotating).
        files.current().writeText("node")
        val oldId = MeshIdentity.shortId(context, oldKey)

        val next = files.rotate()

        assertFalse("the retired generation's short-id entry must be gone", prefsHas(oldKey))
        val newId = MeshIdentity.shortId(context, next.name)
        assertFalse("the rotated node must get a different id", oldId.contentEquals(newId))
    }

    @Test
    fun rotate_never_touches_another_inboxes_short_id() {
        val a = MeshNodeFiles(tmp.root, inboxA, context)
        val b = MeshNodeFiles(tmp.root, inboxB, context)
        a.current().writeText("a")
        val bKey = b.current().name
        b.current().writeText("b")
        val bId = MeshIdentity.shortId(context, bKey)

        a.rotate()

        assertTrue("inbox B's short-id entry must be untouched by inbox A's rotate", prefsHas(bKey))
        assertTrue(bId.contentEquals(MeshIdentity.shortId(context, bKey)))
    }

    @Test
    fun a_missing_context_leaves_rotate_working_but_skips_short_id_cleanup() {
        // Existing callers that construct MeshNodeFiles without a context (e.g. plain-JVM tests)
        // must keep compiling and rotating correctly; they just don't get short-id cleanup.
        val files = MeshNodeFiles(tmp.root, inboxA)
        val old = files.current().apply { writeText("node") }
        files.rotate()
        assertFalse(old.exists())
    }
}
