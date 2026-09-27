package org.xmtp.android.library.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.xmtp.android.library.mesh.link.ShortId

class ShortIdTest {
    @Test
    fun hex_round_trips_and_is_lowercase() {
        val id = byteArrayOf(0, 1, 0x7f, -128, -1, 10, 11, 12)
        assertEquals("00017f80ff0a0b0c", ShortId.hex(id))
        assertArrayEquals(id, ShortId.parse("00017f80ff0a0b0c"))
    }

    @Test
    fun parse_rejects_bad_input() {
        assertNull(ShortId.parse("00017f80ff0a0b0"))
        assertNull(ShortId.parse("00017F80FF0A0B0C"))
        assertNull(ShortId.parse("zz017f80ff0a0b0c"))
    }

    @Test
    fun random_ids_are_8_bytes_and_differ() {
        val a = ShortId.random()
        assertEquals(8, a.size)
        assertFalse(a.contentEquals(ShortId.random()))
    }
}
