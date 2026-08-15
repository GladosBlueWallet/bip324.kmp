package org.bitcoin.bip324

/**
 * BIP-324 shared secret from ephemeral keys.
 * Matches reference.py `v2_ecdh`.
 */
fun v2Ecdh(
    priv: ByteArray,
    ellswiftTheirs: ByteArray,
    ellswiftOurs: ByteArray,
    initiating: Boolean,
): ByteArray {
    val ecdhPointX = ellswiftEcdhXonly(ellswiftTheirs, priv)
    val ordered = if (initiating) {
        concatBytes(ellswiftOurs, ellswiftTheirs, ecdhPointX)
    } else {
        concatBytes(ellswiftTheirs, ellswiftOurs, ecdhPointX)
    }
    return taggedHash("bip324_ellswift_xonly_ecdh", ordered)
}
