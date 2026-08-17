package io.bluewallet.bip324

private val CHACHA20_INDICES = arrayOf(
    intArrayOf(0, 4, 8, 12), intArrayOf(1, 5, 9, 13), intArrayOf(2, 6, 10, 14), intArrayOf(3, 7, 11, 15),
    intArrayOf(0, 5, 10, 15), intArrayOf(1, 6, 11, 12), intArrayOf(2, 7, 8, 13), intArrayOf(3, 4, 9, 14),
)

private val CHACHA20_CONSTANTS = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

private fun rotl32(v: Int, bits: Int): Int = v.rotateLeft(bits)

private fun chacha20DoubleRound(s: IntArray) {
    for (idx in CHACHA20_INDICES) {
        val a = idx[0]
        val b = idx[1]
        val c = idx[2]
        val d = idx[3]
        s[a] = s[a] + s[b]
        s[d] = rotl32(s[d] xor s[a], 16)
        s[c] = s[c] + s[d]
        s[b] = rotl32(s[b] xor s[c], 12)
        s[a] = s[a] + s[b]
        s[d] = rotl32(s[d] xor s[a], 8)
        s[c] = s[c] + s[d]
        s[b] = rotl32(s[b] xor s[c], 7)
    }
}

/** ChaCha20 block: 64 keystream bytes for (key, 12-byte nonce, counter). */
fun chacha20Block(key: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
    require(key.size == 32) { "ChaCha20 key must be 32 bytes" }
    require(nonce.size == 12) { "ChaCha20 nonce must be 12 bytes" }
    val init = IntArray(16)
    for (i in 0 until 4) init[i] = CHACHA20_CONSTANTS[i]
    for (i in 0 until 8) {
        val j = 4 * i
        init[4 + i] = key.u8(j) or (key.u8(j + 1) shl 8) or (key.u8(j + 2) shl 16) or (key.u8(j + 3) shl 24)
    }
    init[12] = counter
    for (i in 0 until 3) {
        val j = 4 * i
        init[13 + i] = nonce.u8(j) or (nonce.u8(j + 1) shl 8) or (nonce.u8(j + 2) shl 16) or (nonce.u8(j + 3) shl 24)
    }
    val state = init.copyOf()
    repeat(10) { chacha20DoubleRound(state) }
    for (i in 0 until 16) state[i] = state[i] + init[i]
    val out = ByteArray(64)
    for (i in 0 until 16) {
        val v = state[i]
        val o = i * 4
        out[o] = v.toByte()
        out[o + 1] = (v ushr 8).toByte()
        out[o + 2] = (v ushr 16).toByte()
        out[o + 3] = (v ushr 24).toByte()
    }
    return out
}

internal fun aeadChacha20Poly1305Encrypt(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    plaintext: ByteArray,
): ByteArray {
    val msgLen = plaintext.size
    val ret = ByteArray(msgLen + 16)
    var i = 0
    while (i * 64 < msgLen) {
        val now = minOf(64, msgLen - 64 * i)
        val keystream = chacha20Block(key, nonce, i + 1)
        for (j in 0 until now) {
            ret[j + 64 * i] = (plaintext[j + 64 * i].toInt() xor keystream[j].toInt()).toByte()
        }
        i += 1
    }
    val poly = Poly1305(chacha20Block(key, nonce, 0).copyOf(32))
    poly.add(aad, pad = true)
    poly.add(ret, length = msgLen, pad = true)
    poly.add(concatBytes(u64le(aad.size.toLong()), u64le(msgLen.toLong())))
    poly.tag().copyInto(ret, msgLen)
    return ret
}

internal fun aeadChacha20Poly1305Decrypt(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    ciphertext: ByteArray,
): ByteArray? {
    if (ciphertext.size < 16) return null
    val msgLen = ciphertext.size - 16
    val poly = Poly1305(chacha20Block(key, nonce, 0).copyOf(32))
    poly.add(aad, pad = true)
    poly.add(ciphertext, length = msgLen, pad = true)
    poly.add(concatBytes(u64le(aad.size.toLong()), u64le(msgLen.toLong())))
    val expected = poly.tag()
    val actual = ciphertext.copyOfRange(msgLen, ciphertext.size)
    if (!equalBytes(expected, actual)) return null
    val ret = ByteArray(msgLen)
    var i = 0
    while (i * 64 < msgLen) {
        val now = minOf(64, msgLen - 64 * i)
        val keystream = chacha20Block(key, nonce, i + 1)
        for (j in 0 until now) {
            ret[j + 64 * i] = (ciphertext[j + 64 * i].toInt() xor keystream[j].toInt()).toByte()
        }
        i += 1
    }
    return ret
}
