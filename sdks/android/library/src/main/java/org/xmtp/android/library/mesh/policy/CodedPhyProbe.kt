package org.xmtp.android.library.mesh.policy

/**
 * Decides whether a link may stay on LE Coded PHY (DESIGN.md §B7). Advertised
 * support is not trusted: the link must actually switch to coded in both
 * directions and carry [probes] acknowledged probe packets.
 */
class CodedPhyProbe(
    private val probes: Int = 5,
) {
    enum class State { IDLE, REQUESTED, PROBING, VERIFIED, REJECTED }

    sealed interface Action {
        object RequestCoded : Action

        data class SendProbes(
            val nonces: List<Int>,
        ) : Action

        object RevertTo1M : Action

        object None : Action
    }

    var state = State.IDLE
        private set

    private val pending = HashSet<Int>()

    fun start(): Action {
        if (state != State.IDLE) return Action.None
        state = State.REQUESTED
        return Action.RequestCoded
    }

    fun onPhyUpdate(
        txCoded: Boolean,
        rxCoded: Boolean,
        success: Boolean,
    ): Action {
        if (state != State.REQUESTED) return Action.None
        if (!(success && txCoded && rxCoded)) return reject()
        state = State.PROBING
        val nonces = (1..probes).toList()
        pending.addAll(nonces)
        return Action.SendProbes(nonces)
    }

    fun onProbeAck(nonce: Int): Action {
        if (state != State.PROBING) return Action.None
        pending.remove(nonce)
        if (pending.isEmpty()) state = State.VERIFIED
        return Action.None
    }

    fun onTimeout(): Action = if (state == State.REQUESTED || state == State.PROBING) reject() else Action.None

    private fun reject(): Action {
        state = State.REJECTED
        pending.clear()
        return Action.RevertTo1M
    }
}
