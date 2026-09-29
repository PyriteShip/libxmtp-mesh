package org.xmtp.android.library.mesh.policy

import kotlin.random.Random

/**
 * Per-peer connect retry schedule. GATT status 133 is the usual failure (DESIGN.md §B7). Holds at
 * most [maxEntries] peers (keys can include rotating addresses): at the cap, expired entries go
 * first, then the oldest.
 */
class BackoffTracker(
    private val baseMs: Long = 1_000,
    private val maxMs: Long = 30_000,
    private val maxAttempts: Int = 5,
    private val cooldownMs: Long = 120_000,
    private val random: Random = Random.Default,
    private val maxEntries: Int = 256,
) {
    private class Entry(
        var failures: Int = 0,
        var nextAllowedMs: Long = 0,
    )

    private val entries = LinkedHashMap<String, Entry>()

    val size: Int get() = entries.size

    private fun entryFor(
        peer: String,
        nowMs: Long,
    ): Entry {
        entries[peer]?.let { return it }
        if (entries.size >= maxEntries) {
            entries.values.removeAll { it.nextAllowedMs <= nowMs }
            while (entries.size >= maxEntries) entries.remove(entries.keys.first())
        }
        return Entry().also { entries[peer] = it }
    }

    fun canAttempt(
        peer: String,
        nowMs: Long,
    ): Boolean = nowMs >= (entries[peer]?.nextAllowedMs ?: 0)

    /** Records a failed connect and returns the delay before the next attempt. */
    fun onFailure(
        peer: String,
        nowMs: Long,
    ): Long {
        val e = entryFor(peer, nowMs)
        e.failures++
        val delay =
            if (e.failures >= maxAttempts) {
                e.failures = 0
                cooldownMs
            } else {
                delayFor(e.failures)
            }
        e.nextAllowedMs = nowMs + delay
        return delay
    }

    fun onSuccess(peer: String) {
        entries.remove(peer)
    }

    /** A success for every peer key starting with [prefix]. */
    fun onSuccessWithPrefix(prefix: String) {
        entries.keys.removeAll { it.startsWith(prefix) }
    }

    /** Keep away from [peer] for the cooldown (e.g. it failed mesh authentication). */
    fun penalize(
        peer: String,
        nowMs: Long,
    ) {
        entryFor(peer, nowMs).nextAllowedMs = nowMs + cooldownMs
    }

    private fun delayFor(failures: Int): Long {
        val raw = minOf(maxMs, baseMs shl (failures - 1).coerceIn(0, 20))
        val jitter = 0.8 + 0.4 * random.nextDouble()
        return (raw * jitter).toLong()
    }
}
