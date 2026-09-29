package org.xmtp.android.library.mesh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * DESIGN.md §B14.1, §B14.7: the node derives its link keys from the account key before sync
 * starts (start_sync refuses without them), a restore opens its window before sync, and the
 * Kotlin copy of the key is wiped. The FFI node can't open in a JVM test, so this reads the
 * source, like MeshStartIdentityOrderTest.
 */
class MeshStartKeyOrderTest {
    private val code =
        File("src/main/java/org/xmtp/android/library/mesh/Mesh.kt")
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    @Test
    fun theAccountKeyAndTheRestoreWindowComeBeforeSync() {
        val start = code.indexOf("suspend fun start(")
        val key = code.indexOf("n.setAccountKey(", start)
        val restore = code.indexOf("n.beginRestoreWindow()", start)
        val sync = code.indexOf("n.startSync(", start)
        assertTrue("setAccountKey before beginRestoreWindow", key in (start + 1) until restore)
        assertTrue("beginRestoreWindow before startSync", restore in 0 until sync)
    }

    @Test
    fun theKotlinCopyOfTheKeyIsWiped() {
        val start = code.indexOf("suspend fun start(")
        val end = code.indexOf("suspend fun stop(")
        val body = code.substring(start, end)
        assertTrue(Regex("""finally\s*\{\s*accountKey\.fill\(0\)""").containsMatchIn(body))
    }

    /** The wipe must enclose the lock: a caller cancelled while waiting for it still wipes the key. */
    @Test
    fun theWipeEnclosesTheLock() {
        val start = code.indexOf("suspend fun start(")
        val end = code.indexOf("suspend fun stop(")
        val body = code.substring(start, end)
        assertTrue(
            "start's body must be try { lock.withLock { … } } finally { accountKey.fill(0) }",
            Regex("""\):\s*MeshRadio\s*=\s*try\s*\{\s*lock\.withLock\s*\{""").containsMatchIn(body),
        )
        // Nothing but closing braces between the locked block's end and the wipe.
        assertTrue(
            "the finally closes the outer try",
            Regex("""\}\s*\}\s*finally\s*\{\s*accountKey\.fill\(0\)\s*\}\s*/\*\*""").containsMatchIn(body),
        )
    }
}
