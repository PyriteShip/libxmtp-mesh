package org.xmtp.android.library.mesh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Relay must be applied after startSync (the Rust engine needs sync) and
 * before r.start() (links that come up afterwards advertise relay in Hello). The FFI node
 * can't open in a JVM test, so this reads the source, like MeshStartIdentityOrderTest.
 */
class MeshStartRelayOrderTest {
    private val code =
        File("src/main/java/org/xmtp/android/library/mesh/Mesh.kt")
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    @Test
    fun relayIsAppliedBetweenStartSyncAndRadioStart() {
        val start = code.indexOf("suspend fun start(")
        assertTrue("suspend fun start( found", start >= 0)
        val sync = code.indexOf("n.startSync(", start)
        val apply = code.indexOf("applyRelay(n", start)
        val radio = code.indexOf("r.start()", start)
        assertTrue("startSync before applyRelay", sync in 0 until apply)
        assertTrue("applyRelay before r.start()", apply in 0 until radio)
    }

    @Test
    fun stopEndsTheBatteryWatch() {
        val stop = code.indexOf("suspend fun stop(")
        assertTrue("suspend fun stop( found", stop >= 0)
        assertTrue(code.indexOf("battery?.stop()", stop) > stop)
    }

    /**
     * `start`'s `relay` default must read the recorded user choice, not a bare
     * `true`, so a prior [Mesh.setRelayEnabled] made while stopped is honored by the next start.
     */
    @Test
    fun startsRelayDefaultReadsTheRecordedChoice() {
        val start = code.indexOf("suspend fun start(")
        assertTrue("suspend fun start( found", start >= 0)
        val signatureEnd = code.indexOf(": MeshRadio =", start)
        assertTrue("start's signature found", signatureEnd > start)
        val signature = code.substring(start, signatureEnd)
        assertTrue(
            "relay defaults from MeshRelayControl.current().userEnabled",
            signature.contains("relay: Boolean = MeshRelayControl.current().userEnabled"),
        )
    }
}
