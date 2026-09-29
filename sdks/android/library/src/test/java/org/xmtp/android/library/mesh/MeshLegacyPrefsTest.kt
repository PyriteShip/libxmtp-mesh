package org.xmtp.android.library.mesh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** DESIGN.md §B14: the short id is gone; the ids older builds stored are deleted, other keys kept. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MeshLegacyPrefsTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun olderShortIdsAreDeleted() {
        val prefs = context.getSharedPreferences("org.xmtp.android.mesh", Context.MODE_PRIVATE)
        prefs
            .edit()
            .putString(
                "short_id",
                "00",
            ).putString("short_id.node-a.db3", "11")
            .putString("other", "keep")
            .commit()
        MeshLegacyPrefs.clear(context)
        assertFalse(prefs.contains("short_id"))
        assertFalse(prefs.contains("short_id.node-a.db3"))
        assertEquals("keep", prefs.getString("other", null))
    }
}
