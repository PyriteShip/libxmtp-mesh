package org.xmtp.android.library.mesh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.AddressCooldown

/** Inbound strangers closed over the relay cap stay away for a while (DESIGN.md §B7.2). */
class AddressCooldownTest {
    @Test
    fun anAddressCoolsDownForItsPeriod() {
        val c = AddressCooldown(periodMs = 30_000)
        assertFalse(c.active("AA", 0))
        c.start("AA", 1_000)
        assertTrue(c.active("AA", 1_000))
        assertTrue(c.active("AA", 30_999))
        assertFalse(c.active("AA", 31_000))
        assertFalse(c.active("BB", 1_000))
    }

    @Test
    fun staysBounded() {
        val c = AddressCooldown(periodMs = 30_000, max = 2)
        c.start("A", 0)
        c.start("B", 0)
        c.start("C", 0)
        assertFalse(c.active("A", 1))
        assertTrue(c.active("B", 1))
        assertTrue(c.active("C", 1))
    }
}
