package org.xmtp.android.library.mesh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PureLayersTest {
    @Test
    fun link_and_policy_do_not_import_android() {
        for (dir in listOf("link", "policy")) {
            val root = File("src/main/java/org/xmtp/android/library/mesh/$dir")
            assertTrue("missing $root (run from the library module)", root.isDirectory)
            root.walk().filter { it.extension == "kt" }.forEach { file ->
                val offending = file.readLines().filter { it.startsWith("import android") }
                assertTrue("$file imports Android: $offending", offending.isEmpty())
            }
        }
    }
}
