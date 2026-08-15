package org.bitcoin.bip324

private const val LENGTH_FIELD_LEN = 3
private const val HEADER_LEN = 1
private const val IGNORE_BIT_POS = 7
private const val CHACHA20POLY1305_EXPANSION = 16

/**
 * Default cap on decrypted packet contents. Bitcoin Core rejects application
 * messages above `MAX_PROTOCOL_MESSAGE_LENGTH` (4_000_000); the extra 13
 * bytes cover the largest BIP-324 message-type prefix (long command form).
 */
const val MAX_CONTENTS_LEN = 4_000_013

/** Consecutive ignore-bit packets skipped per `decodePacket` call. */
const val MAX_IGNORE_PACKETS = 256

class DecodePacketOpts(
    val aad: ByteArray = ByteArray(0),
    val maxContentsLen: Int = MAX_CONTENTS_LEN,
    val maxIgnorePackets: Int = MAX_IGNORE_PACKETS,
    /**
     * When true (default, matches BIP-324 reference), a decode failure
     * immediately zeroizes the session. Protocol defers this to avoid
     * racing a concurrent send.
     */
    val destroyOnError: Boolean = true,
)

/**
 * Decrypt packets until a non-decoy contents buffer is returned.
 * Matches BIP reference `v2_receive_packet` (skips ignore-bit packets).
 */
suspend fun decodePacket(
    session: CipherSession,
    reader: ByteReader,
    opts: DecodePacketOpts = DecodePacketOpts(),
): ByteArray {
    try {
        var aad = opts.aad
        var ignored = 0
        while (true) {
            val encLen = readExactly(reader, LENGTH_FIELD_LEN)
            val lenBytes = session.recvL.decrypt(encLen)
            val contentsLen = lenBytes.u8(0) or (lenBytes.u8(1) shl 8) or (lenBytes.u8(2) shl 16)
            if (contentsLen > opts.maxContentsLen) {
                throw IllegalStateException(
                    "packet contents length $contentsLen exceeds max ${opts.maxContentsLen}",
                )
            }
            val aeadLen = HEADER_LEN + contentsLen + CHACHA20POLY1305_EXPANSION
            val aeadCiphertext = readExactly(reader, aeadLen)
            val plaintext = session.recvP.decrypt(aad, aeadCiphertext)
                ?: throw AuthenticationError()
            aad = ByteArray(0)
            val header = plaintext.u8(0)
            val contents = plaintext.copyOfRange(HEADER_LEN, plaintext.size)
            if ((header and (1 shl IGNORE_BIT_POS)) == 0) return contents
            ignored += 1
            if (ignored > opts.maxIgnorePackets) {
                throw IllegalStateException("too many consecutive decoy packets ($ignored)")
            }
        }
    } catch (error: Throwable) {
        if (opts.destroyOnError) destroySession(session)
        throw error
    }
}

suspend fun decodePacket(
    session: CipherSession,
    duplex: ByteDuplex,
    opts: DecodePacketOpts = DecodePacketOpts(),
): ByteArray = decodePacket(
    session,
    object : ByteReader {
        override suspend fun read(n: Int): ByteArray = duplex.read(n)
    },
    opts,
)
