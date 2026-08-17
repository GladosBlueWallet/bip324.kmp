package io.bluewallet.bip324

/**
 * Rekeying AEAD for BIP-324 packet content.
 * Matches reference.py `FSChaCha20Poly1305`.
 */
class FSChaCha20Poly1305(initialKey: ByteArray) {
    private var key: ByteArray
    private var packetCounter = 0
    private var destroyed = false

    init {
        require(initialKey.size == 32) { "FSChaCha20Poly1305 key must be 32 bytes" }
        key = initialKey.copyOf()
    }

    private fun nonce(): ByteArray =
        concatBytes(u32le(packetCounter % REKEY_INTERVAL), u64le((packetCounter / REKEY_INTERVAL).toLong()))

    private fun maybeRekey() {
        if ((packetCounter + 1) % REKEY_INTERVAL == 0) {
            val nonce = nonce()
            val rekeyNonce = concatBytes(byteArrayOf(0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte()), nonce.copyOfRange(4, 12))
            val nextKey = chacha20Block(key, rekeyNonce, 1).copyOf(32)
            key.fillZero()
            key = nextKey
        }
        packetCounter += 1
    }

    fun encrypt(aad: ByteArray, plaintext: ByteArray): ByteArray {
        if (destroyed) throw IllegalStateException("FSChaCha20Poly1305 instance is destroyed")
        val out = aeadChacha20Poly1305Encrypt(key, nonce(), aad, plaintext)
        maybeRekey()
        return out
    }

    /** Returns null on authentication failure (matches BIP reference). */
    fun decrypt(aad: ByteArray, ciphertext: ByteArray): ByteArray? {
        if (destroyed) throw IllegalStateException("FSChaCha20Poly1305 instance is destroyed")
        return try {
            aeadChacha20Poly1305Decrypt(key, nonce(), aad, ciphertext)
        } finally {
            maybeRekey()
        }
    }

    fun destroy() {
        key.fillZero()
        destroyed = true
    }
}
