package org.xmtp.android.library.mesh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.xmtp.android.library.mesh.link.ShortId

/**
 * D22: the BLE short id is keyed to the node (the inbox + generation encoded in
 * [MeshNodeFiles]'s node file name), not the app install, so a new identity or a rotated node
 * gets a fresh, unlinkable id while restarting the same node keeps its id.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MeshIdentityTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    private val nodeA = "xmtp-mesh-node-${"a".repeat(64)}-0.db3"
    private val nodeB = "xmtp-mesh-node-${"b".repeat(64)}-0.db3"

    @Test
    fun the_same_node_key_gives_the_same_id_across_restarts() {
        val first = MeshIdentity.shortId(context, nodeA)
        val second = MeshIdentity.shortId(context, nodeA)
        assertArrayEquals("restarting the same node must keep its id", first, second)
    }

    @Test
    fun a_different_node_key_gives_a_different_id() {
        val a = MeshIdentity.shortId(context, nodeA)
        val b = MeshIdentity.shortId(context, nodeB)
        assertFalse("a new inbox's node must get its own id", a.contentEquals(b))
    }

    @Test
    fun forgetting_a_node_key_makes_the_next_lookup_mint_a_fresh_id() {
        val before = MeshIdentity.shortId(context, nodeA)
        MeshIdentity.forget(context, nodeA)
        val after = MeshIdentity.shortId(context, nodeA)
        assertFalse("a retired generation must never get its old id back", before.contentEquals(after))
    }

    @Test
    fun forgetting_one_node_key_leaves_others_alone() {
        val a = MeshIdentity.shortId(context, nodeA)
        val b = MeshIdentity.shortId(context, nodeB)
        MeshIdentity.forget(context, nodeA)
        assertArrayEquals("an unrelated node's id must be untouched", b, MeshIdentity.shortId(context, nodeB))
        assertFalse(a.contentEquals(MeshIdentity.shortId(context, nodeA)))
    }

    /**
     * D22, no migration: an "adopt the legacy id" migration could hand a pre-fix install-wide id to a
     * brand-new identity's node (any node whose file didn't exist yet), recreating the exact
     * linkage D22 removes. Pairing does not depend on the short id, so there is nothing
     * to preserve: every node — including one that already existed before the upgrade — gets a
     * fresh random id on its first post-upgrade lookup, and the legacy device-wide entry is
     * simply deleted, never read.
     */
    @Test
    fun a_fresh_node_never_gets_the_legacy_id() {
        val prefs = context.getSharedPreferences("org.xmtp.android.mesh", Context.MODE_PRIVATE)
        val legacy = ShortId.random()
        prefs.edit().putString("short_id", ShortId.hex(legacy)).apply()

        val id = MeshIdentity.shortId(context, nodeA)

        assertFalse("no node may ever adopt the legacy device-wide id", id.contentEquals(legacy))
    }

    @Test
    fun the_legacy_key_is_gone_after_the_first_lookup() {
        val prefs = context.getSharedPreferences("org.xmtp.android.mesh", Context.MODE_PRIVATE)
        prefs.edit().putString("short_id", ShortId.hex(ShortId.random())).apply()

        MeshIdentity.shortId(context, nodeA)

        assertFalse("the legacy key must be deleted, not merely ignored", prefs.contains("short_id"))
    }
}
