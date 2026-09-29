package org.xmtp.android.library.mesh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * DESIGN.md §B14.2: the radio advertises only the node's service data and sends only the
 * node's token in its link Hello. If the node cannot give its advert state, the radio start
 * fails and is retried with the restart backoff; it never comes up with an all-zero token.
 * MeshRadio needs the FFI node and the Bluetooth stack, so this reads the source, like
 * MeshStartKeyOrderTest.
 */
class MeshRadioAdvertStartTest {
    private val code =
        File("src/main/java/org/xmtp/android/library/mesh/MeshRadio.kt")
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    @Test
    fun aMissingAdvertStateIsAFailedStart() {
        val powerUp = code.indexOf("private fun powerUp()")
        val body = code.substring(powerUp, code.indexOf("private fun scheduleRestart(", powerUp))
        assertTrue(
            "powerUp must retry with the restart backoff when readAdvertState fails",
            Regex("""if\s*\(\s*!readAdvertState\(\)\s*\)\s*\{\s*scheduleRestart\([^)]*\)\s*return\s*\}""")
                .containsMatchIn(body),
        )
        val check = body.indexOf("readAdvertState()")
        assertTrue(
            "the advert check comes before the GATT server opens",
            check in 0 until body.indexOf("GattServerHost("),
        )
        assertTrue("and before the radio reports up", check < body.indexOf("up.value = true"))
    }
}
