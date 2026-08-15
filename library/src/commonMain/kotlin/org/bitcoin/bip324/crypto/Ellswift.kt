package org.bitcoin.bip324

data class EllswiftKeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EllswiftKeyPair) return false
        return privateKey.contentEquals(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int = 31 * privateKey.contentHashCode() + publicKey.contentHashCode()
}

private val MINUS_3_SQRT: Fe = Fe(-3).sqrt() ?: error("sqrt(-3) must exist")

internal fun xswiftec(u0: Fe, t0: Fe): Fe {
    var u = u0
    var t = t0
    if (u == Fe.ZERO) u = Fe.ONE
    if (t == Fe.ZERO) t = Fe.ONE
    if (u.pow(3) + t.pow(2) + 7 == Fe.ZERO) t = t * 2
    val x = (u.pow(3) + 7 - t.pow(2)) / (t * 2)
    val y = (x + t) / (MINUS_3_SQRT * u)
    val candidates = arrayOf(
        u + y.pow(2) * 4,
        ((-x) / y - u) / 2,
        (x / y - u) / 2,
    )
    for (cand in candidates) {
        if (Ge.isValidX(cand)) return cand
    }
    error("xswiftec produced no valid x coordinate")
}

/** Decode a 64-byte ElligatorSwift encoding to a 32-byte x-only pubkey. */
fun ellswiftDecode(ellswift: ByteArray): ByteArray {
    require(ellswift.size == 64) { "ellswift must be 64 bytes, got ${ellswift.size}" }
    val u = Fe.fromBytesMod(ellswift.copyOfRange(0, 32))
    val t = Fe.fromBytesMod(ellswift.copyOfRange(32, 64))
    return xswiftec(u, t).toBytes()
}

/**
 * Low-level xswiftec inverse used by ElligatorSwift encoding.
 * Returns null when the selected inverse branch has no solution.
 */
fun xswiftecInv(xBytes: ByteArray, uBytes: ByteArray, ellCase: Int): ByteArray? {
    require(xBytes.size == 32 && uBytes.size == 32) { "x and u must be 32 bytes" }
    require(ellCase in 0..7) { "ElligatorSwift case must be in [0, 7], got $ellCase" }
    val x = Fe.fromBytesMod(xBytes)
    val u = Fe.fromBytesMod(uBytes)
    val t = xswiftecInvFe(x, u, ellCase) ?: return null
    return t.toBytes()
}

internal fun xswiftecInvFe(x: Fe, u: Fe, case: Int): Fe? {
    val v: Fe
    val s: Fe
    if (case and 2 == 0) {
        if (Ge.isValidX(-x - u)) return null
        v = x
        s = -(u.pow(3) + 7) / (u.pow(2) + u * v + v.pow(2))
    } else {
        s = x - u
        if (s == Fe.ZERO) return null
        val r = ((-s) * ((u.pow(3) + 7) * 4 + s * u.pow(2) * 3)).sqrt() ?: return null
        if ((case and 1) != 0 && r == Fe.ZERO) return null
        v = (-u + r / s) / 2
    }
    val w = s.sqrt() ?: return null
    return when (case and 5) {
        0 -> -w * (u * (Fe.ONE - MINUS_3_SQRT) / 2 + v)
        1 -> w * (u * (Fe.ONE + MINUS_3_SQRT) / 2 + v)
        4 -> w * (u * (Fe.ONE - MINUS_3_SQRT) / 2 + v)
        5 -> -w * (u * (Fe.ONE + MINUS_3_SQRT) / 2 + v)
        else -> error("unreachable ellswift case")
    }
}

internal fun xelligatorswift(x: Fe): Pair<Fe, Fe> {
    val random = ByteArray(33)
    while (true) {
        fillSecureRandom(random)
        val u = Fe.fromBytesMod(random.copyOfRange(0, 32))
        if (u == Fe.ZERO) continue
        val t = xswiftecInvFe(x, u, random[32].toInt() and 7) ?: continue
        return u to t
    }
}

/** Generate ephemeral (privateKey, ellswiftPublicKey) pair. */
fun ellswiftCreate(): EllswiftKeyPair {
    while (true) {
        val privateKey = ByteArray(32)
        fillSecureRandom(privateKey)
        if (!isValidSecretScalar(privateKey)) continue
        val pub = Ge.G * privateKey ?: continue
        val (u, t) = xelligatorswift(pub.x)
        return EllswiftKeyPair(privateKey, concatBytes(u.toBytes(), t.toBytes()))
    }
}

/**
 * X-only ECDH: shared X coordinate from our privkey and their ellswift pubkey.
 * Matches BIP reference `ellswift_ecdh_xonly`.
 */
fun ellswiftEcdhXonly(pubkeyTheirs: ByteArray, privkey: ByteArray): ByteArray {
    val pubX = Fe.fromBytes(ellswiftDecode(pubkeyTheirs))
        ?: error("decoded ellswift x is out of range")
    val point = Ge.liftX(pubX) ?: error("decoded ellswift x is not on curve")
    val shared = point * privkey ?: error("ECDH produced infinity")
    return shared.x.toBytes()
}
