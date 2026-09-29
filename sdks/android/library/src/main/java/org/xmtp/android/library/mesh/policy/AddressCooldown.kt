package org.xmtp.android.library.mesh.policy

/**
 * GATT addresses kept away for [periodMs] (DESIGN.md §B7.2): an inbound stranger we closed over
 * the relay cap is refused for a while instead of redialing at once. Best effort: addresses
 * rotate. Bounded: the oldest entry goes first. Radio thread only.
 */
class AddressCooldown(
    private val periodMs: Long = 30_000,
    private val max: Int = 64,
) {
    private val until = LinkedHashMap<String, Long>()

    fun start(
        address: String,
        nowMs: Long,
    ) {
        until.remove(address)
        until.entries.removeAll { it.value <= nowMs }
        if (until.size >= max) until.remove(until.keys.first())
        until[address] = nowMs + periodMs
    }

    fun active(
        address: String,
        nowMs: Long,
    ): Boolean = (until[address] ?: Long.MIN_VALUE) > nowMs

    fun clear() = until.clear()
}
