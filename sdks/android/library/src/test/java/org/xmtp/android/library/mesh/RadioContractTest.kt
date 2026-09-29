package org.xmtp.android.library.mesh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * xmtp_mesh MeshTransport contract: `send` and `disconnect` never call back into the node
 * synchronously (the node calls them under its locks). They only post to the radio thread.
 * MeshRadio needs Bluetooth, so this reads the source, like MeshStartIdentityOrderTest.
 */
class RadioContractTest {
    private val code =
        File("src/main/java/org/xmtp/android/library/mesh/MeshRadio.kt")
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    private fun beforePost(fn: String): String {
        val start = code.indexOf("override fun $fn(")
        assertTrue("override fun $fn found", start >= 0)
        val post = code.indexOf("post(\"$fn\")", start)
        assertTrue("$fn posts to the radio thread", post > start)
        return code.substring(start, post)
    }

    @Test
    fun sendAndDisconnectNeverReenterTheNode() {
        for (fn in listOf("send", "disconnect")) {
            assertFalse("$fn calls the node before posting", beforePost(fn).contains("node."))
        }
    }
}
