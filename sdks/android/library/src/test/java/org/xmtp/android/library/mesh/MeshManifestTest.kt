package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class MeshManifestTest {
    private val ns = "http://schemas.android.com/apk/res/android"

    private fun manifest(): Element {
        val file = File("src/main/AndroidManifest.xml")
        assertTrue("missing $file (run from the library module)", file.isFile)
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        return factory.newDocumentBuilder().parse(file).documentElement
    }

    private fun elements(
        root: Element,
        tag: String,
    ): List<Element> {
        val nodes = root.getElementsByTagName(tag)
        return (0 until nodes.length).map { nodes.item(it) as Element }
    }

    private fun permissions(): Map<String, Element> =
        elements(manifest(), "uses-permission").associateBy { it.getAttributeNS(ns, "name") }

    @Test
    fun declares_ble_permissions_for_api_31_and_up() {
        val perms = permissions()
        for (p in listOf("BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT")) {
            assertNotNull("missing $p", perms["android.permission.$p"])
        }
        assertEquals(
            "neverForLocation",
            perms.getValue("android.permission.BLUETOOTH_SCAN").getAttributeNS(ns, "usesPermissionFlags"),
        )
    }

    @Test
    fun legacy_bluetooth_permissions_stop_at_api_30() {
        val perms = permissions()
        for (p in listOf("BLUETOOTH", "BLUETOOTH_ADMIN", "ACCESS_FINE_LOCATION")) {
            val e = perms["android.permission.$p"]
            assertNotNull("missing $p", e)
            assertEquals("$p maxSdkVersion", "30", e!!.getAttributeNS(ns, "maxSdkVersion"))
        }
    }

    @Test
    fun declares_foreground_service_permissions() {
        val perms = permissions()
        for (p in listOf(
            "FOREGROUND_SERVICE",
            "FOREGROUND_SERVICE_CONNECTED_DEVICE",
            "POST_NOTIFICATIONS",
            "INTERNET",
        )) {
            assertNotNull("missing $p", perms["android.permission.$p"])
        }
    }

    @Test
    fun declares_the_connected_device_foreground_service() {
        val service =
            elements(manifest(), "service").single {
                it.getAttributeNS(ns, "name") == "org.xmtp.android.library.mesh.MeshForegroundService"
            }
        assertEquals("false", service.getAttributeNS(ns, "exported"))
        assertEquals("connectedDevice", service.getAttributeNS(ns, "foregroundServiceType"))
    }
}
