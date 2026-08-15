package org.bitcoin.bip324

class VersionHandshakeOptions(
    val port: Int,
    /** Application name from the main app (e.g. package.json `name`). */
    val name: String,
    /** Application version from the main app (e.g. package.json `version`). */
    val version: String,
    /** Height we advertise in our version message (default 0). */
    val startHeight: Int = 0,
    /** Service flags we advertise (default 0). */
    val services: ULong = 0uL,
    /**
     * After the peer's version, send `sendaddrv2` before verack.
     * Default true (matches Bitcoin Core peers).
     */
    val sendAddrV2: Boolean = true,
)

class VersionHandshakeResult(
    /** Peer's advertised service flags. */
    val services: ULong,
    /** Peer's advertised start height. */
    val startHeight: Int,
)

private const val MAX_VERSION_HANDSHAKE_MESSAGES = 32

/** Reply to ping; no-op for other commands. */
suspend fun answerPing(protocol: Protocol, message: Message) {
    if (message is Message.Ping) {
        protocol.writeMessage(Message.Pong(message.nonce))
    }
}

/**
 * Bitcoin P2P application handshake (version / verack) on an already-connected
 * BIP-324 `Protocol` session.
 */
suspend fun completeVersionHandshake(
    protocol: Protocol,
    options: VersionHandshakeOptions,
): VersionHandshakeResult {
    val sendAddrV2 = options.sendAddrV2
    val random = ByteArray(8)
    fillSecureRandom(random)
    var nonce = 0uL
    for (i in 0 until 8) nonce = nonce or (random.u8(i).toULong() shl (8 * i))

    protocol.writeMessage(
        Message.Version(
            VersionPayload(
                version = 70_016,
                services = options.services,
                timestamp = currentEpochSeconds(),
                receiver = NetworkAddress(0uL, ByteArray(16), options.port),
                sender = NetworkAddress(0uL, ByteArray(16), 0),
                nonce = nonce,
                userAgent = "/${options.name}:${options.version}/",
                startHeight = options.startHeight,
                relay = false,
            ),
        ),
    )

    var receivedVersion = false
    var receivedVerack = false
    var peerServices = 0uL
    var peerStartHeight = 0
    var seen = 0

    while (!receivedVersion || !receivedVerack) {
        if (seen >= MAX_VERSION_HANDSHAKE_MESSAGES) {
            throw IllegalStateException("version handshake exceeded message limit")
        }
        seen += 1
        val message = protocol.readMessage()
        when (message) {
            is Message.Version -> {
                if (receivedVersion) continue
                receivedVersion = true
                peerServices = message.payload.services
                peerStartHeight = message.payload.startHeight
                if (sendAddrV2) {
                    protocol.writeMessage(
                        Message.Opaque(
                            type = WireMessageType.Long("sendaddrv2"),
                            payload = ByteArray(0),
                        ),
                    )
                }
                protocol.writeMessage(Message.Verack)
            }
            is Message.Verack -> receivedVerack = true
            else -> answerPing(protocol, message)
        }
    }

    return VersionHandshakeResult(peerServices, peerStartHeight)
}
