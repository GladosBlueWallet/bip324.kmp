package io.bluewallet.bip324

private const val LENGTH_FIELD_LEN = 3
private const val HEADER_LEN = 1
private const val IGNORE_BIT_POS = 7

class EncodePacketOpts(
    val aad: ByteArray = ByteArray(0),
    val ignore: Boolean = false,
)

/** Encrypt a BIP-324 packet (length || AEAD(header||contents)). */
fun encodePacket(
    session: CipherSession,
    contents: ByteArray,
    opts: EncodePacketOpts = EncodePacketOpts(),
): ByteArray {
    if (contents.size > 0xffffff) {
        throw IllegalArgumentException("contents too large: ${contents.size}")
    }
    val header = ByteArray(HEADER_LEN)
    header[0] = if (opts.ignore) (1 shl IGNORE_BIT_POS).toByte() else 0
    val plaintext = ByteArray(HEADER_LEN + contents.size)
    plaintext[0] = header[0]
    contents.copyInto(plaintext, HEADER_LEN)
    val aeadCiphertext = session.sendP.encrypt(opts.aad, plaintext)
    val lenBytes = byteArrayOf(
        (contents.size and 0xff).toByte(),
        ((contents.size ushr 8) and 0xff).toByte(),
        ((contents.size ushr 16) and 0xff).toByte(),
    )
    val encLen = session.sendL.encrypt(lenBytes)
    return concatBytes(encLen, aeadCiphertext)
}

fun encodePacket(
    session: CipherSession,
    contents: ByteArray,
    aad: ByteArray = ByteArray(0),
    ignore: Boolean = false,
): ByteArray = encodePacket(session, contents, EncodePacketOpts(aad, ignore))
