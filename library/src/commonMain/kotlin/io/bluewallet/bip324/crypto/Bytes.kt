package io.bluewallet.bip324

fun concatBytes(vararg parts: ByteArray): ByteArray {
    var len = 0
    for (p in parts) len += p.size
    val out = ByteArray(len)
    var offset = 0
    for (p in parts) {
        p.copyInto(out, offset)
        offset += p.size
    }
    return out
}

fun equalBytes(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
}

fun hexToBytes(hex: String): ByteArray {
    if (hex.length % 2 != 0) throw IllegalArgumentException("odd hex length: ${hex.length}")
    if (!HEX_RE.matches(hex)) throw IllegalArgumentException("invalid hex string")
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
    return out
}

fun bytesToHex(bytes: ByteArray): String {
    val chars = CharArray(bytes.size * 2)
    for (i in bytes.indices) {
        val v = bytes[i].toInt() and 0xff
        chars[i * 2] = HEX_DIGITS[v ushr 4]
        chars[i * 2 + 1] = HEX_DIGITS[v and 0x0f]
    }
    return chars.concatToString()
}

internal fun u32le(n: Int): ByteArray {
    val v = n.toLong() and 0xffff_ffffL
    return byteArrayOf(
        (v and 0xff).toByte(),
        ((v ushr 8) and 0xff).toByte(),
        ((v ushr 16) and 0xff).toByte(),
        ((v ushr 24) and 0xff).toByte(),
    )
}

internal fun u64le(n: Long): ByteArray {
    val v = n.toULong()
    return byteArrayOf(
        (v and 0xffu).toByte(),
        ((v shr 8) and 0xffu).toByte(),
        ((v shr 16) and 0xffu).toByte(),
        ((v shr 24) and 0xffu).toByte(),
        ((v shr 32) and 0xffu).toByte(),
        ((v shr 40) and 0xffu).toByte(),
        ((v shr 48) and 0xffu).toByte(),
        ((v shr 56) and 0xffu).toByte(),
    )
}

internal fun ByteArray.u8(i: Int): Int = this[i].toInt() and 0xff

internal fun ByteArray.fillZero() {
    fill(0)
}

internal fun ByteArray.copyOfRangeSafe(start: Int, end: Int): ByteArray {
    return copyOfRange(start, end.coerceAtMost(size).coerceAtLeast(start))
}

private val HEX_RE = Regex("^[0-9a-fA-F]*$")
private val HEX_DIGITS = charArrayOf(
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
)
