package org.bitcoin.bip324

/**
 * Minimal byte-stream duplex injected by the host runtime.
 *
 * `read(n)` may return between 1 and n bytes. It returns an empty array only
 * after EOF. The protocol buffers fragmented reads internally.
 */
interface ByteDuplex {
    suspend fun read(n: Int): ByteArray
    suspend fun write(bytes: ByteArray)
    suspend fun close()
}

interface ByteReader {
    /** Return 0 at EOF, or between 1 and n bytes. */
    suspend fun read(n: Int): ByteArray
}

/** Read exactly n bytes, accepting arbitrary stream fragmentation. */
suspend fun readExactly(reader: ByteReader, n: Int): ByteArray {
    require(n >= 0) { "invalid read length: $n" }
    val out = ByteArray(n)
    var offset = 0
    while (offset < n) {
        val chunk = reader.read(n - offset)
        if (chunk.isEmpty()) {
            throw IllegalStateException("unexpected EOF: wanted $n bytes, got $offset")
        }
        if (chunk.size > n - offset) {
            throw IllegalStateException(
                "reader returned ${chunk.size} bytes when at most ${n - offset} were requested",
            )
        }
        chunk.copyInto(out, offset)
        offset += chunk.size
    }
    return out
}

suspend fun readExactly(duplex: ByteDuplex, n: Int): ByteArray =
    readExactly(
        object : ByteReader {
            override suspend fun read(n: Int): ByteArray = duplex.read(n)
        },
        n,
    )
