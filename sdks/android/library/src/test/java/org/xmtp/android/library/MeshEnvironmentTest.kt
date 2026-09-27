package org.xmtp.android.library

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import org.xmtp.android.library.mesh.MeshOptions

class MeshEnvironmentTest {
    @Test
    fun meshRawValueRoundTrips() {
        assertEquals(XMTPEnvironment.MESH, XMTPEnvironment("mesh"))
    }

    @Test
    fun meshHasNoHistorySyncServer() {
        assertEquals("", XMTPEnvironment.MESH.getHistorySyncUrl())
    }

    @Test
    fun meshWithoutOptionsIsRejected() {
        assertThrows(XMTPException::class.java) {
            Client.requireMeshOptions(ClientOptions.Api(env = XMTPEnvironment.MESH))
        }
    }

    @Test
    fun meshOptionsAreCarriedByApi() {
        val options = MeshOptions("/tmp/mesh-test/node.db3", ByteArray(32))
        val api = ClientOptions.Api(env = XMTPEnvironment.MESH, isSecure = false, mesh = options)
        assertSame(options, Client.requireMeshOptions(api))
    }

    @Test
    fun meshOptionsRejectShortKey() {
        assertThrows(IllegalArgumentException::class.java) {
            MeshOptions("/tmp/mesh-test/node.db3", ByteArray(31))
        }
    }
}
