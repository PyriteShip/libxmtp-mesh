package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.MeshPermissions

class MeshPermissionsTest {
    @Test
    fun android_12_plus_needs_the_three_bluetooth_permissions() {
        assertEquals(
            listOf(
                "android.permission.BLUETOOTH_SCAN",
                "android.permission.BLUETOOTH_ADVERTISE",
                "android.permission.BLUETOOTH_CONNECT",
            ),
            MeshPermissions.required(31),
        )
    }

    @Test
    fun android_11_and_below_needs_fine_location() {
        assertEquals(listOf("android.permission.ACCESS_FINE_LOCATION"), MeshPermissions.required(30))
    }

    @Test
    fun android_13_also_requests_notifications_for_the_foreground_service() {
        assertTrue("android.permission.POST_NOTIFICATIONS" in MeshPermissions.requested(33))
        assertTrue("android.permission.POST_NOTIFICATIONS" !in MeshPermissions.requested(32))
    }
}
