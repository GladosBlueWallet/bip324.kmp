package io.bluewallet.bip324.helpers

fun parseCsv(text: String): List<Map<String, String>> {
    val lines = text.replace("\r\n", "\n").trim().split('\n').filter { it.isNotEmpty() }
    if (lines.isEmpty()) return emptyList()
    val headers = lines[0].split(',')
    return lines.drop(1).map { line ->
        val cols = line.split(',')
        headers.mapIndexed { i, header -> header to (cols.getOrElse(i) { "" }) }.toMap()
    }
}

class BufferReader(private val data: ByteArray) : io.bluewallet.bip324.ByteReader {
    var offset: Int = 0
        private set

    override suspend fun read(n: Int): ByteArray {
        val end = minOf(offset + n, data.size)
        val chunk = data.copyOfRange(offset, end)
        offset = end
        return chunk
    }
}

class FragmentingReader(
    private val data: ByteArray,
    private val maxChunk: Int,
) : io.bluewallet.bip324.ByteReader {
    var offset: Int = 0
        private set

    override suspend fun read(n: Int): ByteArray {
        val length = minOf(n, maxChunk, data.size - offset)
        if (length <= 0) return ByteArray(0)
        val chunk = data.copyOfRange(offset, offset + length)
        offset += length
        return chunk
    }
}
