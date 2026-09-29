package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test
import org.xmtp.android.library.mesh.policy.AdvertCache
import org.xmtp.android.library.mesh.policy.AdvertMatch

/** One classifyAdvert per advert per window and contacts version, not one per sighting. */
class AdvertCacheTest {
    @Test
    fun classifiesOncePerWindowAndVersion() {
        val cache = AdvertCache(max = 2)
        var calls = 0
        val classify = {
            calls++
            AdvertMatch.Contact("bob", true)
        }
        cache.get("aa", window = 1, version = 1, classify = classify)
        cache.get("aa", 1, 1, classify)
        assertEquals(1, calls)
        cache.get("aa", 1, 2, classify)
        assertEquals(2, calls)
        cache.get("aa", 2, 2, classify)
        assertEquals(3, calls)
    }

    /** A removed, forgotten or reset contact moves the version: its old Contact answer is gone. */
    @Test
    fun aContactNeverOutlivesAVersionChange() {
        val cache = AdvertCache()
        cache.get("aa", 1, 1) { AdvertMatch.Contact("bob", true) }
        assertEquals(AdvertMatch.Stranger(false, true), cache.get("aa", 1, 2) { AdvertMatch.Stranger(false, true) })
        // Going back to an older version (a new node) is a change too.
        assertEquals(AdvertMatch.Ignore, cache.get("aa", 1, 1) { AdvertMatch.Ignore })
    }

    @Test
    fun staysBounded() {
        val cache = AdvertCache(max = 2)
        var calls = 0
        val classify = {
            calls++
            AdvertMatch.Ignore
        }
        cache.get("a", 1, 1, classify)
        cache.get("b", 1, 1, classify)
        cache.get("c", 1, 1, classify)
        cache.get("a", 1, 1, classify)
        assertEquals(4, calls)
    }

    /** A failed classification (the node threw) is not an answer: the next sighting asks again. */
    @Test
    fun aFailedClassificationIsNeverCached() {
        val cache = AdvertCache()
        var calls = 0
        assertEquals(
            null,
            cache.get("aa", 1, 1) {
                calls++
                null
            },
        )
        assertEquals(
            AdvertMatch.Contact("bob", true),
            cache.get("aa", 1, 1) {
                calls++
                AdvertMatch.Contact("bob", true)
            },
        )
        assertEquals(2, calls)
    }
}
