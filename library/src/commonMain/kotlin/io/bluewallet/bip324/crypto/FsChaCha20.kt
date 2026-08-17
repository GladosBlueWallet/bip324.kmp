package io.bluewallet.bip324

const val REKEY_INTERVAL = 224

/**
 * Rekeying stream cipher for BIP-324 length encryption.
 * Matches reference.py `FSChaCha20`.
 */
class FSChaCha20(initialKey: ByteArray) {
    private var key: ByteArray
    private var blockCounter = 0
    private var chunkCounter = 0
    private var keystream = ByteArray(0)
    private var destroyed = false

    init {
        require(initialKey.size == 32) { "FSChaCha20 key must be 32 bytes" }
        key = initialKey.copyOf()
    }

    private fun getKeystreamBytes(nbytes: Int): ByteArray {
        val parts = ArrayList<ByteArray>()
        var have = keystream.size
        if (have > 0) parts.add(keystream)
        while (have < nbytes) {
            val nonce = concatBytes(u32le(0), u64le((chunkCounter / REKEY_INTERVAL).toLong()))
            val block = chacha20Block(key, nonce, blockCounter)
            blockCounter += 1
            parts.add(block)
            have += block.size
        }
        val all = concatBytes(*parts.toTypedArray())
        val ret = all.copyOf(nbytes)
        keystream = all.copyOfRange(nbytes, all.size)
        return ret
    }

    fun crypt(chunk: ByteArray): ByteArray {
        if (destroyed) throw IllegalStateException("FSChaCha20 instance is destroyed")
        val ks = getKeystreamBytes(chunk.size)
        val ret = ByteArray(chunk.size)
        for (i in chunk.indices) ret[i] = (chunk[i].toInt() xor ks[i].toInt()).toByte()
        if ((chunkCounter + 1) % REKEY_INTERVAL == 0) {
            val nextKey = getKeystreamBytes(32)
            key.fillZero()
            key = nextKey
            blockCounter = 0
        }
        chunkCounter += 1
        return ret
    }

    fun encrypt(chunk: ByteArray): ByteArray = crypt(chunk)

    fun decrypt(chunk: ByteArray): ByteArray = crypt(chunk)

    fun destroy() {
        key.fillZero()
        keystream.fillZero()
        keystream = ByteArray(0)
        destroyed = true
    }
}
