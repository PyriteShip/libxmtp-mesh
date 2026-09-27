package org.xmtp.android.library.mesh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * D22: [Mesh.start] must derive the short id from the node file it is about to open
 * (inbox + generation), not from the app install alone, so the id [MeshRadio] advertises and
 * puts in the HELLO follows the current node. `MeshRadio.localShortIdHex`, its advertisement
 * ([MeshRadio.advertisement]) and [org.xmtp.android.library.mesh.policy.PeerTable]'s own-id all
 * come from the single `localShortId` constructor argument wired up here, and a fresh MeshRadio
 * is constructed on every [Mesh.start] (nothing else caches the id across a stop/start — see
 * [Mesh.stop] clearing `radio`), so this one call site is what needs to be right. A Service/FFI
 * node can't be opened in a plain JVM test, so this reads the source (comments stripped), the
 * same technique as [MeshForegroundServiceStopTest].
 */
class MeshStartShortIdTest {
    private val code =
        File("src/main/java/org/xmtp/android/library/mesh/Mesh.kt")
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    @Test
    fun start_keys_the_short_id_to_the_node_file_being_opened() {
        assertTrue(
            "Mesh.start must call MeshIdentity.shortId with the node file's name (D22)",
            Regex("""MeshIdentity\.shortId\(\s*app\s*,\s*File\(options\.dbPath\)\.name\s*\)""").containsMatchIn(code),
        )
    }
}
