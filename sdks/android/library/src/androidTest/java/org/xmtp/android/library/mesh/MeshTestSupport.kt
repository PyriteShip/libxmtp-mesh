package org.xmtp.android.library.mesh

import kotlinx.coroutines.delay
import org.junit.Assert.fail
import org.xmtp.android.library.Client

internal suspend fun eventually(
    what: String,
    timeoutMs: Long = 60_000,
    check: suspend () -> Boolean,
) {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (!check()) {
        if (System.currentTimeMillis() > deadline) fail("timed out waiting for: $what")
        delay(250)
    }
}

internal suspend fun <T> retrying(
    what: String,
    timeoutMs: Long,
    block: suspend () -> T,
): T {
    val deadline = System.currentTimeMillis() + timeoutMs
    var last: Throwable? = null
    while (System.currentTimeMillis() < deadline) {
        try {
            return block()
        } catch (e: Exception) {
            last = e
            delay(500)
        }
    }
    throw AssertionError("gave up on: $what", last)
}

internal suspend fun hasMessage(
    client: Client,
    text: String,
): Boolean {
    runCatching { client.conversations.syncAllConversations() }
    return client.conversations.listDms().any { dm -> dm.messages().any { it.body == text } }
}
