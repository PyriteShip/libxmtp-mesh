package org.xmtp.android.library.mesh.link

/** One BLE write or notification. Big-endian. See the KDoc on each type (DESIGN.md §B7.1). */
sealed class LinkPacket {
    abstract fun encode(): ByteArray

    /**
     * First packet each way. The central sends first; the peripheral answers. [token] is 8 zero
     * bytes: the field stays for the wire format, and nothing reads it (DESIGN.md §B14.2).
     */
    class Hello(
        val version: Int,
        val token: ByteArray,
        val flags: Int,
        val window: Int,
    ) : LinkPacket() {
        val codedHint: Boolean get() = (flags and FLAG_CODED_HINT) != 0

        override fun encode(): ByteArray =
            byteArrayOf(TYPE_HELLO.toByte(), version.toByte()) + token +
                byteArrayOf(flags.toByte(), window.toByte())
    }

    /** Chunk [index] of [count] of frame [msgId]. */
    class Data(
        val msgId: Int,
        val index: Int,
        val count: Int,
        val payload: ByteArray,
    ) : LinkPacket() {
        override fun encode(): ByteArray {
            val out = ByteArray(DATA_HEADER_BYTES + payload.size)
            out[0] = TYPE_DATA.toByte()
            putU16(out, 1, msgId)
            putU16(out, 3, index)
            putU16(out, 5, count)
            payload.copyInto(out, DATA_HEADER_BYTES)
            return out
        }
    }

    data class Ack(
        val msgId: Int,
        val index: Int,
    ) : LinkPacket() {
        override fun encode(): ByteArray =
            ByteArray(5).also {
                it[0] = TYPE_ACK.toByte()
                putU16(it, 1, msgId)
                putU16(it, 3, index)
            }
    }

    data class Probe(
        val nonce: Int,
    ) : LinkPacket() {
        override fun encode(): ByteArray =
            ByteArray(3).also {
                it[0] = TYPE_PROBE.toByte()
                putU16(it, 1, nonce)
            }
    }

    data class ProbeAck(
        val nonce: Int,
    ) : LinkPacket() {
        override fun encode(): ByteArray =
            ByteArray(3).also {
                it[0] = TYPE_PROBE_ACK.toByte()
                putU16(it, 1, nonce)
            }
    }

    data class Bye(
        val reason: Int,
    ) : LinkPacket() {
        override fun encode(): ByteArray = byteArrayOf(TYPE_BYE.toByte(), reason.toByte())
    }

    companion object {
        const val LINK_VERSION = 2
        const val TOKEN_BYTES = 8
        const val FLAG_CODED_HINT = 0x01
        const val DATA_HEADER_BYTES = 7
        const val BYE_NORMAL = 0

        private const val TYPE_HELLO = 0x01
        private const val TYPE_DATA = 0x02
        private const val TYPE_ACK = 0x03
        private const val TYPE_PROBE = 0x04
        private const val TYPE_PROBE_ACK = 0x05
        private const val TYPE_BYE = 0x06
        private const val HELLO_BYTES = 2 + TOKEN_BYTES + 2

        /** Returns null for anything malformed or unknown; callers ignore null. */
        fun decode(bytes: ByteArray): LinkPacket? {
            if (bytes.isEmpty()) return null
            return when (u8(bytes, 0)) {
                TYPE_HELLO ->
                    if (bytes.size < HELLO_BYTES) {
                        null
                    } else {
                        Hello(u8(bytes, 1), bytes.copyOfRange(2, 2 + TOKEN_BYTES), u8(bytes, 10), u8(bytes, 11))
                    }
                TYPE_DATA -> {
                    if (bytes.size <= DATA_HEADER_BYTES) return null
                    val index = getU16(bytes, 3)
                    val count = getU16(bytes, 5)
                    if (count == 0 || index >= count) {
                        null
                    } else {
                        Data(getU16(bytes, 1), index, count, bytes.copyOfRange(DATA_HEADER_BYTES, bytes.size))
                    }
                }
                TYPE_ACK -> if (bytes.size < 5) null else Ack(getU16(bytes, 1), getU16(bytes, 3))
                TYPE_PROBE -> if (bytes.size < 3) null else Probe(getU16(bytes, 1))
                TYPE_PROBE_ACK -> if (bytes.size < 3) null else ProbeAck(getU16(bytes, 1))
                TYPE_BYE -> if (bytes.size < 2) null else Bye(u8(bytes, 1))
                else -> null
            }
        }

        internal fun putU16(
            b: ByteArray,
            at: Int,
            v: Int,
        ) {
            b[at] = ((v ushr 8) and 0xFF).toByte()
            b[at + 1] = (v and 0xFF).toByte()
        }

        internal fun getU16(
            b: ByteArray,
            at: Int,
        ): Int = ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

        private fun u8(
            b: ByteArray,
            at: Int,
        ): Int = b[at].toInt() and 0xFF
    }
}
