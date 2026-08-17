package io.bluewallet.bip324

sealed interface WireMessageType {
    data class Short(val id: Int) : WireMessageType
    data class Long(val command: String) : WireMessageType
}

sealed interface Message {
    val command: String

    data class Version(val payload: VersionPayload) : Message {
        override val command: String = "version"
    }

    data object Verack : Message {
        override val command: String = "verack"
    }

    data class Ping(val nonce: ByteArray) : Message {
        override val command: String = "ping"
        override fun equals(other: Any?): Boolean =
            other is Ping && nonce.contentEquals(other.nonce)
        override fun hashCode(): Int = nonce.contentHashCode()
    }

    data class Pong(val nonce: ByteArray) : Message {
        override val command: String = "pong"
        override fun equals(other: Any?): Boolean =
            other is Pong && nonce.contentEquals(other.nonce)
        override fun hashCode(): Int = nonce.contentHashCode()
    }

    data object GetAddr : Message {
        override val command: String = "getaddr"
    }

    data class GetHeaders(val payload: GetHeadersPayload) : Message {
        override val command: String = "getheaders"
    }

    data class Headers(val payload: HeadersPayload) : Message {
        override val command: String = "headers"
    }

    data class GetData(val payload: InventoryPayload) : Message {
        override val command: String = "getdata"
    }

    data class Inv(val payload: InventoryPayload) : Message {
        override val command: String = "inv"
    }

    data class NotFound(val payload: InventoryPayload) : Message {
        override val command: String = "notfound"
    }

    data class Block(val payload: BlockPayload) : Message {
        override val command: String = "block"
    }

    data class Tx(val payload: Transaction) : Message {
        override val command: String = "tx"
    }

    data class Addr(val payload: AddrPayload) : Message {
        override val command: String = "addr"
    }

    data class AddrV2(val payload: AddrV2Payload) : Message {
        override val command: String = "addrv2"
    }

    data class Opaque(val type: WireMessageType, val payload: ByteArray) : Message {
        override val command: String = "opaque"
        override fun equals(other: Any?): Boolean =
            other is Opaque && type == other.type && payload.contentEquals(other.payload)
        override fun hashCode(): Int = 31 * type.hashCode() + payload.contentHashCode()
    }
}

private fun encodeLongCommand(command: String): ByteArray {
    if (command.isEmpty() || command.length > 12) {
        throw IllegalArgumentException("command length must be in [1, 12], got ${command.length}")
    }
    for (ch in command) {
        val code = ch.code
        if (code < 0x20 || code > 0x7e) {
            throw IllegalArgumentException("command must contain printable ASCII only")
        }
    }
    val out = ByteArray(13)
    for (i in command.indices) out[i + 1] = command[i].code.toByte()
    return out
}

private fun encodeCommand(command: String): ByteArray {
    val shortId = SHORT_MESSAGE_IDS[command]
    return if (shortId != null) byteArrayOf(shortId.toByte()) else encodeLongCommand(command)
}

private class DecodedCommand(
    val command: String?,
    val type: WireMessageType,
    val headerLen: Int,
)

private fun decodeCommand(bytes: ByteArray): DecodedCommand {
    if (bytes.isEmpty()) throw IllegalArgumentException("empty message contents")
    val first = bytes.u8(0)
    if (first == 0) {
        if (bytes.size < 13) throw IllegalArgumentException("truncated long command")
        val raw = bytes.copyOfRange(1, 13)
        val nul = raw.indexOf(0)
        val end = if (nul == -1) raw.size else nul
        if (end == 0) throw IllegalArgumentException("long command must not be empty")
        for (i in 0 until end) {
            val b = raw.u8(i)
            if (b < 0x20 || b > 0x7e) {
                throw IllegalArgumentException("long command must contain printable ASCII only")
            }
        }
        for (i in end until raw.size) {
            if (raw[i] != 0.toByte()) throw IllegalArgumentException("nonzero byte after long command padding")
        }
        val command = buildString {
            for (i in 0 until end) append(raw.u8(i).toChar())
        }
        return DecodedCommand(command, WireMessageType.Long(command), 13)
    }
    val command = SHORT_ID_TO_COMMAND[first]
    return DecodedCommand(command, WireMessageType.Short(first), 1)
}

private fun frame(command: String, payload: ByteArray): ByteArray {
    val header = encodeCommand(command)
    return concatBytes(header, payload)
}

/** Encode application-layer contents (pre-packet encryption). */
fun encodeMessage(msg: Message): ByteArray {
    return when (msg) {
        is Message.Verack, is Message.GetAddr -> encodeCommand(msg.command)
        is Message.Ping -> {
            if (msg.nonce.size != 8) throw IllegalArgumentException("ping nonce must be 8 bytes")
            concatBytes(encodeCommand("ping"), msg.nonce)
        }
        is Message.Pong -> {
            if (msg.nonce.size != 8) throw IllegalArgumentException("pong nonce must be 8 bytes")
            concatBytes(encodeCommand("pong"), msg.nonce)
        }
        is Message.Opaque -> {
            val hdr = when (val type = msg.type) {
                is WireMessageType.Short -> {
                    if (type.id < 1 || type.id > 255) {
                        throw IllegalArgumentException("short message ID must be in [1, 255], got ${type.id}")
                    }
                    byteArrayOf(type.id.toByte())
                }
                is WireMessageType.Long -> encodeLongCommand(type.command)
            }
            concatBytes(hdr, msg.payload)
        }
        is Message.Version -> frame(msg.command, encodeVersion(msg.payload))
        is Message.Addr -> frame(msg.command, encodeAddr(msg.payload))
        is Message.AddrV2 -> frame(msg.command, encodeAddrV2(msg.payload))
        is Message.GetHeaders -> frame(msg.command, encodeGetHeaders(msg.payload))
        is Message.Headers -> frame(msg.command, encodeHeaders(msg.payload))
        is Message.GetData -> frame(msg.command, encodeInventory(msg.payload))
        is Message.Inv -> frame(msg.command, encodeInventory(msg.payload))
        is Message.NotFound -> frame(msg.command, encodeInventory(msg.payload))
        is Message.Block -> frame(msg.command, encodeBlock(msg.payload))
        is Message.Tx -> frame(msg.command, encodeTransaction(msg.payload))
    }
}

/** Decode application-layer contents after packet decryption. */
fun decodeMessage(contents: ByteArray): Message {
    val decoded = decodeCommand(contents)
    val payload = contents.copyOfRange(decoded.headerLen, contents.size)
    return when (decoded.command) {
        "verack" -> {
            if (payload.isNotEmpty()) throw IllegalArgumentException("verack payload must be empty")
            Message.Verack
        }
        "getaddr" -> {
            if (payload.isNotEmpty()) throw IllegalArgumentException("getaddr payload must be empty")
            Message.GetAddr
        }
        "ping" -> {
            if (payload.size != 8) throw IllegalArgumentException("ping payload must be 8 bytes")
            Message.Ping(payload)
        }
        "pong" -> {
            if (payload.size != 8) throw IllegalArgumentException("pong payload must be 8 bytes")
            Message.Pong(payload)
        }
        "version" -> Message.Version(decodeVersion(payload))
        "getheaders" -> Message.GetHeaders(decodeGetHeaders(payload))
        "headers" -> Message.Headers(decodeHeaders(payload))
        "getdata" -> Message.GetData(decodeInventory(payload))
        "inv" -> Message.Inv(decodeInventory(payload))
        "notfound" -> Message.NotFound(decodeInventory(payload))
        "block" -> Message.Block(decodeBlock(payload))
        "tx" -> Message.Tx(decodeTransaction(payload))
        "addr" -> Message.Addr(decodeAddr(payload))
        "addrv2" -> Message.AddrV2(decodeAddrV2(payload))
        else -> Message.Opaque(decoded.type, payload)
    }
}
