package org.xmtp.android.library.mesh

import android.app.ActivityManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The stop race, without the radio: a STOP delivered right behind a START must
 * still let the service call startForeground, or Android kills the process
 * ("did not then call Service.startForeground()") within a few seconds. Needs no
 * Bluetooth permission: on API 34+ without it, startForeground is refused and the
 * service stops itself, which must not crash either.
 */
@RunWith(AndroidJUnit4::class)
class MeshForegroundServiceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun stopRightAfterStartDoesNotCrash() =
        runBlocking {
            repeat(3) {
                MeshForegroundService.start(context)
                MeshForegroundService.stop(context)
            }
            // The platform's startForeground deadline is 5 s (10 s on older releases);
            // the test process would be killed inside this window if a start went unanswered.
            eventually("service stopped", 15_000) { !serviceRunning() }
            delay(11_000)
            assertFalse("service came back", serviceRunning())
        }

    @Suppress("DEPRECATION") // still reports the caller's own services
    private fun serviceRunning(): Boolean =
        (context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager)
            .getRunningServices(Int.MAX_VALUE)
            .any { it.service.className == MeshForegroundService::class.java.name }
}
