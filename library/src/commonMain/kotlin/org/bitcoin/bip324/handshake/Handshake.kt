package org.bitcoin.bip324

enum class Role {
    Initiator,
    Responder,
}

sealed interface HandshakeResult {
    val transport: String
}

class V2HandshakeResult(
    val session: CipherSession,
    val role: Role,
) : HandshakeResult {
    override val transport: String = "v2"
}

class V1HandshakeResult(
    /** Bytes already consumed from the stream; prepend these for a v1 parser. */
    val buffered: ByteArray,
) : HandshakeResult {
    override val transport: String = "v1"
}

class HandshakeOptions(
    val role: Role,
    val network: Network,
    val garbage: ByteArray = ByteArray(0),
    /** Injectable only to support deterministic transcript/interoperability tests. */
    val createKeyPair: () -> EllswiftKeyPair = { ellswiftCreate() },
)

private const val MAX_GARBAGE = 4095

private fun v1Prefix(magic: ByteArray): ByteArray {
    val cmd = utf8ToBytes("version")
    val padded = ByteArray(12)
    cmd.copyInto(padded)
    return concatBytes(magic, padded)
}

private suspend fun readUntilTerminator(
    duplex: ByteDuplex,
    terminator: ByteArray,
): ByteArray {
    var buf = ByteArray(0)
    while (buf.size < terminator.size) {
        buf = concatBytes(buf, readExactly(duplex, 1))
    }
    for (i in 0..MAX_GARBAGE) {
        if (equalBytes(buf.copyOfRange(buf.size - terminator.size, buf.size), terminator)) {
            return buf.copyOf(buf.size - terminator.size)
        }
        buf = concatBytes(buf, readExactly(duplex, 1))
    }
    throw IllegalStateException("garbage terminator not found")
}

/**
 * Complete BIP-324 handshake over a duplex.
 * Negotiates empty transport version packets after key exchange.
 */
suspend fun performHandshake(
    duplex: ByteDuplex,
    opts: HandshakeOptions,
): HandshakeResult {
    if (opts.garbage.size > MAX_GARBAGE) throw IllegalArgumentException("garbage too long")
    return if (opts.role == Role.Initiator) {
        initiatorHandshake(duplex, opts.network, opts.garbage, opts.createKeyPair)
    } else {
        responderHandshake(duplex, opts.network, opts.garbage, opts.createKeyPair)
    }
}

private suspend fun initiatorHandshake(
    duplex: ByteDuplex,
    network: Network,
    sentGarbage: ByteArray,
    createKeyPair: () -> EllswiftKeyPair,
): V2HandshakeResult {
    val keyPair = createKeyPair()
    val privateKey = keyPair.privateKey
    var ecdh: ByteArray? = null
    var session: CipherSession? = null
    try {
        duplex.write(concatBytes(keyPair.publicKey, sentGarbage))
        val ellswiftTheirs = readExactly(duplex, 64)
        ecdh = v2Ecdh(privateKey, ellswiftTheirs, keyPair.publicKey, true)
        session = deriveSessionKeys(ecdh, network.magic, true)
        ecdh.fillZero()
        ecdh = null

        duplex.write(session.sendGarbageTerminator)
        duplex.write(encodePacket(session, ByteArray(0), aad = sentGarbage))

        val receivedGarbage = readUntilTerminator(duplex, session.recvGarbageTerminator)
        decodePacket(session, duplex, DecodePacketOpts(aad = receivedGarbage))
        return V2HandshakeResult(session, Role.Initiator)
    } catch (error: Throwable) {
        session?.let { destroySession(it) }
        throw error
    } finally {
        ecdh?.fillZero()
        privateKey.fillZero()
    }
}

private suspend fun responderHandshake(
    duplex: ByteDuplex,
    network: Network,
    sentGarbage: ByteArray,
    createKeyPair: () -> EllswiftKeyPair,
): HandshakeResult {
    val prefixWanted = v1Prefix(network.magic)
    var receivedPrefix = ByteArray(0)
    while (receivedPrefix.size < prefixWanted.size) {
        val b = readExactly(duplex, 1)
        receivedPrefix = concatBytes(receivedPrefix, b)
        if (receivedPrefix.last() != prefixWanted[receivedPrefix.size - 1]) {
            break
        }
    }
    if (receivedPrefix.size == prefixWanted.size && equalBytes(receivedPrefix, prefixWanted)) {
        return V1HandshakeResult(receivedPrefix)
    }

    val keyPair = createKeyPair()
    val privateKey = keyPair.privateKey
    var ecdh: ByteArray? = null
    var session: CipherSession? = null
    try {
        duplex.write(concatBytes(keyPair.publicKey, sentGarbage))
        val remaining = 64 - receivedPrefix.size
        val rest = if (remaining > 0) readExactly(duplex, remaining) else ByteArray(0)
        val ellswiftTheirs = concatBytes(receivedPrefix, rest)
        if (ellswiftTheirs.size != 64) throw IllegalStateException("incomplete ellswift key")

        val versionPad = ByteArray(12)
        utf8ToBytes("version").copyInto(versionPad)
        if (equalBytes(ellswiftTheirs.copyOfRange(4, 16), versionPad)) {
            throw IllegalStateException("peer appears to be v1 on a different network")
        }

        ecdh = v2Ecdh(privateKey, ellswiftTheirs, keyPair.publicKey, false)
        session = deriveSessionKeys(ecdh, network.magic, false)
        ecdh.fillZero()
        ecdh = null

        duplex.write(session.sendGarbageTerminator)
        duplex.write(encodePacket(session, ByteArray(0), aad = sentGarbage))

        val receivedGarbage = readUntilTerminator(duplex, session.recvGarbageTerminator)
        decodePacket(session, duplex, DecodePacketOpts(aad = receivedGarbage))
        return V2HandshakeResult(session, Role.Responder)
    } catch (error: Throwable) {
        session?.let { destroySession(it) }
        throw error
    } finally {
        ecdh?.fillZero()
        privateKey.fillZero()
    }
}
