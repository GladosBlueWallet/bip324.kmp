package io.bluewallet.bip324

/** Single SHA-256. */
fun sha256Once(data: ByteArray): ByteArray = Sha256.hash(data)

/** Double SHA-256 (Bitcoin txid / block hash / merkle). */
fun sha256d(data: ByteArray): ByteArray = Sha256.hash(Sha256.hash(data))

/** BIP-340 tagged hash: SHA256(SHA256(tag)||SHA256(tag)||data) */
fun taggedHash(tag: String, data: ByteArray): ByteArray {
    val tagHash = Sha256.hash(utf8ToBytes(tag))
    return Sha256.hash(concatBytes(tagHash, tagHash, data))
}

internal fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val block = ByteArray(64)
    if (key.size > 64) {
        Sha256.hash(key).copyInto(block)
    } else {
        key.copyInto(block)
    }
    val ipad = ByteArray(64)
    val opad = ByteArray(64)
    for (i in 0 until 64) {
        ipad[i] = (block[i].toInt() xor 0x36).toByte()
        opad[i] = (block[i].toInt() xor 0x5c).toByte()
    }
    return Sha256.hash(concatBytes(opad, Sha256.hash(concatBytes(ipad, data))))
}

/** HKDF-SHA256 extract+expand to `length` bytes. */
fun hkdfSha256(
    ikm: ByteArray,
    salt: ByteArray,
    info: ByteArray,
    length: Int,
): ByteArray {
    val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
    val prk = hmacSha256(actualSalt, ikm)
    var t = ByteArray(0)
    val okm = ArrayList<Byte>(length)
    var i = 1
    while (okm.size < length) {
        t = hmacSha256(prk, concatBytes(t, info, byteArrayOf(i.toByte())))
        for (b in t) {
            if (okm.size < length) okm.add(b)
        }
        i += 1
    }
    return okm.toByteArray()
}

fun hkdfSha256(
    ikm: ByteArray,
    salt: ByteArray,
    info: String,
    length: Int,
): ByteArray = hkdfSha256(ikm, salt, utf8ToBytes(info), length)
