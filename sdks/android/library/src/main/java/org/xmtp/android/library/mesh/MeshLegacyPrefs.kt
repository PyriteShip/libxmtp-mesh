package org.xmtp.android.library.mesh

import android.content.Context

/**
 * Older builds kept a BLE short id per node in these preferences (D22), a stable identifier
 * that private discovery (DESIGN.md §B14) replaced with rotating tokens. Deleted on start.
 */
internal object MeshLegacyPrefs {
    private const val PREFS = "org.xmtp.android.mesh"

    fun clear(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stale = prefs.all.keys.filter { it == "short_id" || it.startsWith("short_id.") }
        if (stale.isEmpty()) return
        val edit = prefs.edit()
        stale.forEach { edit.remove(it) }
        edit.commit()
    }
}
