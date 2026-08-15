package org.bitcoin.bip324

fun utf8ToBytes(value: String): ByteArray = value.encodeToByteArray()

fun bytesToUtf8(bytes: ByteArray): String {
    val output = StringBuilder()
    val units = StringBuilder()
    fun flush() {
        if (units.isNotEmpty()) {
            output.append(units)
            units.clear()
        }
    }
    fun continuation(index: Int): Int {
        if (index >= bytes.size) throw IllegalArgumentException("invalid UTF-8")
        val byte = bytes[index].toInt() and 0xff
        if ((byte and 0xc0) != 0x80) throw IllegalArgumentException("invalid UTF-8")
        return byte
    }

    var i = 0
    while (i < bytes.size) {
        val first = bytes[i++].toInt() and 0xff
        val codePoint: Int
        when {
            first <= 0x7f -> codePoint = first
            first in 0xc2..0xdf -> {
                codePoint = ((first and 0x1f) shl 6) or (continuation(i++) and 0x3f)
            }
            first in 0xe0..0xef -> {
                val second = continuation(i++)
                val third = continuation(i++)
                if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0)) {
                    throw IllegalArgumentException("invalid UTF-8")
                }
                codePoint = ((first and 0x0f) shl 12) or ((second and 0x3f) shl 6) or (third and 0x3f)
            }
            first in 0xf0..0xf4 -> {
                val second = continuation(i++)
                val third = continuation(i++)
                val fourth = continuation(i++)
                if ((first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90)) {
                    throw IllegalArgumentException("invalid UTF-8")
                }
                codePoint =
                    ((first and 0x07) shl 18) or
                        ((second and 0x3f) shl 12) or
                        ((third and 0x3f) shl 6) or
                        (fourth and 0x3f)
            }
            else -> throw IllegalArgumentException("invalid UTF-8")
        }

        if (codePoint <= 0xffff) {
            units.append(codePoint.toChar())
        } else {
            val adjusted = codePoint - 0x10000
            units.append((0xd800 + (adjusted shr 10)).toChar())
            units.append((0xdc00 + (adjusted and 0x3ff)).toChar())
        }
        if (units.length >= 4096) flush()
    }
    flush()
    return output.toString()
}
