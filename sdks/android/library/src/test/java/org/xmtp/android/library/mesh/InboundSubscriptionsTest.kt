package org.xmtp.android.library.mesh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xmtp.android.library.mesh.policy.InboundSubscriptions

class InboundSubscriptionsTest {
    @Test
    fun first_enable_is_a_new_link_and_a_repeat_is_not() {
        val s = InboundSubscriptions()
        assertTrue(s.enable("s:AA"))
        assertFalse(s.enable("s:AA"))
        assertTrue(s.contains("s:AA"))
    }

    /**
     * A non-hard peripheral close left the key subscribed, so a
     * central that re-subscribed over the same ACL was ignored until the ACL dropped.
     */
    @Test
    fun after_forget_a_resubscribe_is_a_new_link() {
        val s = InboundSubscriptions()
        s.enable("s:AA")
        s.forget("s:AA")
        assertFalse(s.contains("s:AA"))
        assertTrue(s.enable("s:AA"))
    }

    @Test
    fun disable_and_disconnect_report_only_a_subscribed_key() {
        val s = InboundSubscriptions()
        assertFalse(s.disable("s:AA"))
        assertFalse(s.disconnected("s:AA"))
        s.enable("s:AA")
        assertTrue(s.disconnected("s:AA"))
        assertFalse(s.disable("s:AA"))
    }

    @Test
    fun clear_forgets_everyone() {
        val s = InboundSubscriptions()
        s.enable("s:AA")
        s.enable("s:BB")
        s.clear()
        assertFalse(s.contains("s:AA") || s.contains("s:BB"))
    }
}
