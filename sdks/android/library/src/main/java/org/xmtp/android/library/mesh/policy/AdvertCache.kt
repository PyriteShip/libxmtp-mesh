package org.xmtp.android.library.mesh.policy

/**
 * The node's classification of each seen advert, kept for one window and contacts version, so
 * the radio calls `classifyAdvert` once per advert, not once per sighting (DESIGN.md §B14.2). Any
 * change of window or version (a new window, a pairing, a remove or forget, a key reset) empties
 * it, so a stale Contact answer never outlives the change. A failed classification (null) is
 * returned but never kept. Bounded: the oldest entry goes first. Radio thread only.
 */
class AdvertCache(
    private val max: Int = 256,
) {
    private var window = Long.MIN_VALUE
    private var version = Long.MIN_VALUE
    private val map = LinkedHashMap<String, AdvertMatch>()

    fun get(
        key: String,
        window: Long,
        version: Long,
        classify: () -> AdvertMatch?,
    ): AdvertMatch? {
        if (window != this.window || version != this.version) {
            map.clear()
            this.window = window
            this.version = version
        }
        map[key]?.let { return it }
        val m = classify() ?: return null
        if (map.size >= max) map.remove(map.keys.first())
        map[key] = m
        return m
    }

    fun clear() {
        map.clear()
        window = Long.MIN_VALUE
        version = Long.MIN_VALUE
    }
}
