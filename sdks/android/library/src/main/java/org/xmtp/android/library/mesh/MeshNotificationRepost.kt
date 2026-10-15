package org.xmtp.android.library.mesh

import android.app.Activity
import android.app.Application
import android.os.Bundle

/**
 * Brings back the "Messaging nearby" notification when the app comes to the front. Since
 * Android 14 the user can dismiss a foreground service's notification while the service
 * keeps running; without this it stays gone until the next [Mesh.start]. A dismissal holds
 * until the app is next opened, so the user still controls the shade.
 */
internal class MeshNotificationRepost(
    private val app: Application,
    onFront: () -> Unit,
) : Application.ActivityLifecycleCallbacks {
    private val tracker = AppFrontTracker(startedNow = 1, onFront = onFront)

    fun register() = app.registerActivityLifecycleCallbacks(this)

    fun unregister() = app.unregisterActivityLifecycleCallbacks(this)

    override fun onActivityStarted(activity: Activity) = tracker.activityStarted()

    override fun onActivityStopped(activity: Activity) = tracker.activityStopped()

    override fun onActivityCreated(
        activity: Activity,
        savedInstanceState: Bundle?,
    ) = Unit

    override fun onActivityResumed(activity: Activity) = Unit

    override fun onActivityPaused(activity: Activity) = Unit

    override fun onActivitySaveInstanceState(
        activity: Activity,
        outState: Bundle,
    ) = Unit

    override fun onActivityDestroyed(activity: Activity) = Unit
}
