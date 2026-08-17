package io.bluewallet.bip324

private val MAX_U64 = ULong.MAX_VALUE

class PayloadReader(val data: ByteArray) {
    private var offset = 0

    val remaining: Int
        get() = data.size - offset

    val position: Int
        get() = offset

    fun peekU8(): Int {
        ensure(1)
        return data.u8(offset)
    }

    fun u8(): Int {
        ensure(1)
        return data.u8(offset++)
    }

    fun u16be(): Int = view(2).let { bytes ->
        (bytes.u8(0) shl 8) or bytes.u8(1)
    }

    fun u16le(): Int = view(2).let { bytes ->
        bytes.u8(0) or (bytes.u8(1) shl 8)
    }

    fun u32le(): UInt {
        val bytes = view(4)
        return bytes.u8(0).toUInt() or
            (bytes.u8(1).toUInt() shl 8) or
            (bytes.u8(2).toUInt() shl 16) or
            (bytes.u8(3).toUInt() shl 24)
    }

    fun i32le(): Int = u32le().toInt()

    fun u64le(): ULong {
        val bytes = view(8)
        var v = 0uL
        for (i in 0 until 8) {
            v = v or (bytes.u8(i).toULong() shl (8 * i))
        }
        return v
    }

    fun i64le(): Long = u64le().toLong()

    fun bytes(length: Int): ByteArray {
        require(length >= 0) { "invalid byte length: $length" }
        ensure(length)
        val result = data.copyOfRange(offset, offset + length)
        offset += length
        return result
    }

    fun skip(length: Int) {
        require(length >= 0) { "invalid skip length: $length" }
        ensure(length)
        offset += length
    }

    fun compactSizeULong(): ULong {
        val prefix = u8()
        if (prefix < 0xfd) return prefix.toULong()
        if (prefix == 0xfd) {
            val value = u16le().toULong()
            if (value < 0xfdu) throw IllegalArgumentException("non-canonical CompactSize")
            return value
        }
        if (prefix == 0xfe) {
            val value = u32le().toULong()
            if (value <= 0xffffu) throw IllegalArgumentException("non-canonical CompactSize")
            return value
        }
        val value = u64le()
        if (value <= 0xffff_ffffu) throw IllegalArgumentException("non-canonical CompactSize")
        return value
    }

    fun compactSize(max: Int = Int.MAX_VALUE): Int {
        val value = compactSizeULong()
        if (value > Int.MAX_VALUE.toULong()) {
            throw IllegalArgumentException("CompactSize exceeds safe integer range")
        }
        val number = value.toInt()
        if (number > max) throw IllegalArgumentException("CompactSize $number exceeds limit $max")
        return number
    }

    fun varBytes(max: Int = Int.MAX_VALUE): ByteArray = bytes(compactSize(max))

    fun skipVarBytes(max: Int = Int.MAX_VALUE): Int {
        val length = compactSize(max)
        skip(length)
        return length
    }

    fun varString(max: Int = Int.MAX_VALUE): String = bytesToUtf8(varBytes(max))

    fun finish() {
        if (remaining != 0) throw IllegalArgumentException("$remaining trailing payload bytes")
    }

    private fun ensure(length: Int) {
        if (length > remaining) {
            throw IllegalArgumentException("truncated payload: wanted $length bytes, have $remaining")
        }
    }

    private fun view(length: Int): ByteArray {
        ensure(length)
        val result = data.copyOfRange(offset, offset + length)
        offset += length
        return result
    }
}

class PayloadWriter {
    private val parts = ArrayList<ByteArray>()

    fun u8(value: Int): PayloadWriter {
        integer(value, 0xff, "u8")
        parts.add(byteArrayOf(value.toByte()))
        return this
    }

    fun u16be(value: Int): PayloadWriter {
        integer(value, 0xffff, "u16")
        parts.add(byteArrayOf((value ushr 8).toByte(), value.toByte()))
        return this
    }

    fun u16le(value: Int): PayloadWriter {
        integer(value, 0xffff, "u16")
        parts.add(byteArrayOf(value.toByte(), (value ushr 8).toByte()))
        return this
    }

    fun u32le(value: Int): PayloadWriter = u32le(value.toUInt())

    fun u32le(value: UInt): PayloadWriter {
        parts.add(
            byteArrayOf(
                value.toByte(),
                (value shr 8).toByte(),
                (value shr 16).toByte(),
                (value shr 24).toByte(),
            ),
        )
        return this
    }

    fun i32le(value: Int): PayloadWriter {
        if (value < -0x8000_0000 || value > 0x7fff_ffff) {
            throw IllegalArgumentException("invalid i32: $value")
        }
        return u32le(value.toUInt())
    }

    fun u64le(value: ULong): PayloadWriter {
        parts.add(
            byteArrayOf(
                value.toByte(),
                (value shr 8).toByte(),
                (value shr 16).toByte(),
                (value shr 24).toByte(),
                (value shr 32).toByte(),
                (value shr 40).toByte(),
                (value shr 48).toByte(),
                (value shr 56).toByte(),
            ),
        )
        return this
    }

    fun u64le(value: Long): PayloadWriter {
        require(value >= 0) { "invalid u64: $value" }
        return u64le(value.toULong())
    }

    fun i64le(value: Long): PayloadWriter = u64le(value.toULong())

    fun bytes(value: ByteArray): PayloadWriter {
        parts.add(value.copyOf())
        return this
    }

    fun compactSize(value: ULong): PayloadWriter {
        if (value < 0xfdu) return u8(value.toInt())
        if (value <= 0xffffu) {
            u8(0xfd)
            return u16le(value.toInt())
        }
        if (value <= 0xffff_ffffu) {
            u8(0xfe)
            return u32le(value.toUInt())
        }
        u8(0xff)
        return u64le(value)
    }

    fun compactSize(value: Int): PayloadWriter {
        require(value >= 0) { "invalid CompactSize: $value" }
        return compactSize(value.toULong())
    }

    fun compactSize(value: Long): PayloadWriter {
        require(value >= 0) { "invalid CompactSize: $value" }
        return compactSize(value.toULong())
    }

    fun varBytes(value: ByteArray): PayloadWriter = compactSize(value.size).bytes(value)

    fun varString(value: String): PayloadWriter = varBytes(utf8ToBytes(value))

    fun finish(): ByteArray = concatBytes(*parts.toTypedArray())

    private fun integer(value: Int, max: Int, name: String) {
        if (value < 0 || value > max) throw IllegalArgumentException("invalid $name: $value")
    }
}
