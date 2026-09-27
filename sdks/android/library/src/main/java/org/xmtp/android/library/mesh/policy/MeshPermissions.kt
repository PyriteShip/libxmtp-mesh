package org.xmtp.android.library.mesh.policy

/** Runtime permissions (DESIGN.md §B7), as plain strings so this stays testable on the JVM. */
object MeshPermissions {
    /** Must be granted before the radio starts. */
    fun required(sdkInt: Int): List<String> =
        if (sdkInt >= 31) {
            listOf(
                "android.permission.BLUETOOTH_SCAN",
                "android.permission.BLUETOOTH_ADVERTISE",
                "android.permission.BLUETOOTH_CONNECT",
            )
        } else {
            listOf("android.permission.ACCESS_FINE_LOCATION")
        }

    /** What onboarding should ask for: [required] plus the foreground-service notification. */
    fun requested(sdkInt: Int): List<String> =
        required(sdkInt) + if (sdkInt >= 33) listOf("android.permission.POST_NOTIFICATIONS") else emptyList()
}
