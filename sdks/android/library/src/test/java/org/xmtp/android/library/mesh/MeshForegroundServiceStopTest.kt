package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

/**
 * A fast STOP → START pair must not end with the service destroyed while
 * the radio is up. `stopSelf()` also drops a newer pending start; `stopSelfResult(startId)`
 * stops only when no newer start has arrived. A Service can't run in a plain JVM test, so this
 * reads the source (comments stripped).
 */
class MeshForegroundServiceStopTest {
    private val code =
        File("src/main/java/org/xmtp/android/library/mesh/MeshForegroundService.kt")
            .readLines()
            .map { it.substringBefore("//") }
            .joinToString("\n")

    @Test
    fun onStartCommand_stops_only_its_own_start() {
        assertFalse("bare stopSelf() drops a newer pending start", Regex("""\bstopSelf\(\)""").containsMatchIn(code))
        assertEquals(2, Regex("""\bstopSelfResult\(startId\)""").findAll(code).count())
    }
}
