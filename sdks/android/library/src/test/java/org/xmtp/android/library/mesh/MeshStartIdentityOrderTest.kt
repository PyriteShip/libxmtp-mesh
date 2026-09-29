package org.xmtp.android.library.mesh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `start_sync` spawns the node's identity task, which replays every pending
 * client resync straight away, and a replayed `RebaseNeeded` is broadcast
 * once. [Mesh.start] must subscribe the identity stream before it starts sync, or that event
 * goes out before anyone listens and the re-base waits a whole launch. A Service/FFI node can't
 * be opened in a plain JVM test, so this reads the source (comments stripped), the same
 * technique as [MeshStartKeyOrderTest].
 */
class MeshStartIdentityOrderTest {
    private val code =
        File("src/main/java/org/xmtp/android/library/mesh/Mesh.kt")
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    @Test
    fun start_subscribes_the_identity_stream_before_it_starts_sync() {
        val subscribe = code.indexOf("n.streamIdentity(")
        val sync = code.indexOf("n.startSync(")
        assertTrue("Mesh.start must call streamIdentity and startSync", subscribe >= 0 && sync >= 0)
        assertTrue("Mesh.start must subscribe streamIdentity before startSync", subscribe < sync)
    }
}
