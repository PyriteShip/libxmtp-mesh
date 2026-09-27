package org.xmtp.android.library.mesh

import android.content.Context
import org.xmtp.android.library.mesh.link.ShortId

/**
 * The BLE short id (DESIGN.md D9: cleartext for now) advertised for one mesh node, keyed to [nodeKey]
 * (the node database file name, which [MeshNodeFiles] derives from the inbox id and generation)
 * rather than the app install (D22, DESIGN.md §B10.3): a new identity
 * (fresh inbox) or a rotated node (reset/delete) gets a fresh, unlinkable id, while restarting
 * the same node reuses its id, so peers see a stable id across app restarts for the same
 * identity. [forget] removes an id when its node generation is retired
 * ([MeshNodeFiles.rotate]), so no stale ids are left behind.
 *
 * D22 also means there is no migration of the earlier, device-wide legacy id. That id had
 * already been broadcast next to
 * every identity the install ever used, so handing it to whichever node was looked up first
 * after the upgrade — which can be a brand-new identity's node, since `forClient`/`rotate` mint
 * a fresh generation whenever a node's libxmtp DB doesn't exist yet — recreated the exact
 * linkage this fix removes. Pairing does not depend on the short id (peers relearn it from
 * every advertisement and HELLO), so nothing is lost: every node gets a fresh random id on its
 * first post-upgrade lookup, and the legacy entry is simply deleted, never read.
 */
internal object MeshIdentity {
    private const val PREFS = "org.xmtp.android.mesh"
    private const val KEY_PREFIX = "short_id."

    // D22: the earlier install-wide id lived under this un-keyed name. Never read; always
    // deleted (see shortId).
    private const val LEGACY_KEY = "short_id"

    fun shortId(
        context: Context,
        nodeKey: String,
    ): ByteArray {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val prefKey = KEY_PREFIX + nodeKey
        prefs.getString(prefKey, null)?.let { hex -> ShortId.parse(hex)?.let { return it } }
        val fresh = ShortId.random()
        // commit() (synchronous; callers are already on Dispatchers.IO) so a process death
        // right after this can't leave the legacy key behind for a later lookup to (no longer)
        // read anyway, and can't lose this node's freshly minted id either.
        prefs
            .edit()
            .putString(prefKey, ShortId.hex(fresh))
            .remove(LEGACY_KEY)
            .commit()
        return fresh
    }

    /** Removes [nodeKey]'s stored short id, e.g. when [MeshNodeFiles.rotate] retires it. */
    fun forget(
        context: Context,
        nodeKey: String,
    ) {
        context
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_PREFIX + nodeKey)
            .commit()
    }
}
