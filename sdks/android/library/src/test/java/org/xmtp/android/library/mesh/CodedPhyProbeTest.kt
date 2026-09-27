package org.xmtp.android.library.mesh

import org.junit.Assert.assertEquals
import org.junit.Test
import org.xmtp.android.library.mesh.policy.CodedPhyProbe
import org.xmtp.android.library.mesh.policy.CodedPhyProbe.Action
import org.xmtp.android.library.mesh.policy.CodedPhyProbe.State

class CodedPhyProbeTest {
    @Test
    fun verified_only_after_every_probe_is_acked_on_coded() {
        val p = CodedPhyProbe(probes = 3)
        assertEquals(Action.RequestCoded, p.start())
        assertEquals(Action.SendProbes(listOf(1, 2, 3)), p.onPhyUpdate(txCoded = true, rxCoded = true, success = true))
        p.onProbeAck(1)
        p.onProbeAck(3)
        assertEquals(State.PROBING, p.state)
        p.onProbeAck(2)
        assertEquals(State.VERIFIED, p.state)
        assertEquals(Action.None, p.onTimeout())
    }

    @Test
    fun claimed_support_without_coded_phy_reverts() {
        val p = CodedPhyProbe()
        p.start()
        assertEquals(Action.RevertTo1M, p.onPhyUpdate(txCoded = true, rxCoded = false, success = true))
        assertEquals(State.REJECTED, p.state)
    }

    @Test
    fun missing_probe_acks_revert_on_timeout() {
        val p = CodedPhyProbe()
        p.start()
        p.onPhyUpdate(txCoded = true, rxCoded = true, success = true)
        p.onProbeAck(1)
        assertEquals(Action.RevertTo1M, p.onTimeout())
        assertEquals(State.REJECTED, p.state)
        p.onProbeAck(2)
        assertEquals(State.REJECTED, p.state)
    }

    @Test
    fun no_phy_update_at_all_reverts_on_timeout() {
        val p = CodedPhyProbe()
        p.start()
        assertEquals(Action.RevertTo1M, p.onTimeout())
    }

    @Test
    fun start_is_one_shot_and_stray_updates_are_ignored() {
        val p = CodedPhyProbe()
        assertEquals(Action.None, p.onPhyUpdate(txCoded = true, rxCoded = true, success = true))
        p.start()
        assertEquals(Action.None, p.start())
    }
}
