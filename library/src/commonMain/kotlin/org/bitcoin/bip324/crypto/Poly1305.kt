package org.bitcoin.bip324

/**
 * Poly1305 MAC matching BIP-324 `reference.py` / RFC 8439
 * (32-bit donna limb layout).
 */
internal class Poly1305(key: ByteArray) {
    private val r0: Long
    private val r1: Long
    private val r2: Long
    private val r3: Long
    private val r4: Long
    private val s1: Long
    private val s2: Long
    private val s3: Long
    private val s4: Long
    private val pad0: Long
    private val pad1: Long
    private val pad2: Long
    private val pad3: Long
    private var h0 = 0L
    private var h1 = 0L
    private var h2 = 0L
    private var h3 = 0L
    private var h4 = 0L

    init {
        require(key.size >= 32) { "Poly1305 key must be 32 bytes" }
        r0 = u32le(key, 0) and 0x3ffffff
        r1 = (u32le(key, 3) ushr 2) and 0x3ffff03
        r2 = (u32le(key, 6) ushr 4) and 0x3ffc0ff
        r3 = (u32le(key, 9) ushr 6) and 0x3f03fff
        r4 = (u32le(key, 12) ushr 8) and 0x00fffff
        s1 = r1 * 5
        s2 = r2 * 5
        s3 = r3 * 5
        s4 = r4 * 5
        pad0 = u32le(key, 16)
        pad1 = u32le(key, 20)
        pad2 = u32le(key, 24)
        pad3 = u32le(key, 28)
    }

    fun add(msg: ByteArray, length: Int = msg.size, pad: Boolean = false): Poly1305 {
        var off = 0
        while (off < length) {
            val n = minOf(16, length - off)
            val block = ByteArray(16)
            msg.copyInto(block, 0, off, off + n)
            val hibit = if (pad || n == 16) 1L shl 24 else 0L
            if (!pad && n < 16) {
                block[n] = 1
            }
            process(block, hibit)
            off += n
        }
        return this
    }

    fun tag(): ByteArray {
        var h0 = this.h0
        var h1 = this.h1
        var h2 = this.h2
        var h3 = this.h3
        var h4 = this.h4

        var c = h1 ushr 26; h1 = h1 and 0x3ffffff; h2 += c
        c = h2 ushr 26; h2 = h2 and 0x3ffffff; h3 += c
        c = h3 ushr 26; h3 = h3 and 0x3ffffff; h4 += c
        c = h4 ushr 26; h4 = h4 and 0x3ffffff; h0 += c * 5
        c = h0 ushr 26; h0 = h0 and 0x3ffffff; h1 += c

        var g0 = h0 + 5; c = g0 ushr 26; g0 = g0 and 0x3ffffff
        var g1 = h1 + c; c = g1 ushr 26; g1 = g1 and 0x3ffffff
        var g2 = h2 + c; c = g2 ushr 26; g2 = g2 and 0x3ffffff
        var g3 = h3 + c; c = g3 ushr 26; g3 = g3 and 0x3ffffff
        val g4 = h4 + c - (1L shl 26)

        var mask = g4 shr 63
        h0 = (h0 and mask) or (g0 and mask.inv())
        h1 = (h1 and mask) or (g1 and mask.inv())
        h2 = (h2 and mask) or (g2 and mask.inv())
        h3 = (h3 and mask) or (g3 and mask.inv())
        h4 = (h4 and mask) or (g4 and mask.inv())

        h0 = (h0 or (h1 shl 26)) and 0xffffffffL
        h1 = ((h1 ushr 6) or (h2 shl 20)) and 0xffffffffL
        h2 = ((h2 ushr 12) or (h3 shl 14)) and 0xffffffffL
        h3 = ((h3 ushr 18) or (h4 shl 8)) and 0xffffffffL

        var f = h0 + pad0
        val out = ByteArray(16)
        writeU32le(out, 0, f)
        f = h1 + pad1 + (f ushr 32)
        writeU32le(out, 4, f)
        f = h2 + pad2 + (f ushr 32)
        writeU32le(out, 8, f)
        f = h3 + pad3 + (f ushr 32)
        writeU32le(out, 12, f)
        return out
    }

    private fun process(block: ByteArray, hibit: Long) {
        h0 += u32le(block, 0) and 0x3ffffff
        h1 += (u32le(block, 3) ushr 2) and 0x3ffffff
        h2 += (u32le(block, 6) ushr 4) and 0x3ffffff
        h3 += (u32le(block, 9) ushr 6) and 0x3ffffff
        h4 += (u32le(block, 12) ushr 8) or hibit

        val d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
        val d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
        val d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
        val d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
        val d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

        h0 = d0 and 0x3ffffff
        var c = d0 ushr 26
        var t = d1 + c
        h1 = t and 0x3ffffff
        c = t ushr 26
        t = d2 + c
        h2 = t and 0x3ffffff
        c = t ushr 26
        t = d3 + c
        h3 = t and 0x3ffffff
        c = t ushr 26
        t = d4 + c
        h4 = t and 0x3ffffff
        c = t ushr 26
        h0 += c * 5
        c = h0 ushr 26
        h0 = h0 and 0x3ffffff
        h1 += c
    }

    private companion object {
        fun u32le(bytes: ByteArray, off: Int): Long {
            fun at(i: Int): Long = if (i < bytes.size) bytes[i].toLong() and 0xff else 0L
            return at(off) or (at(off + 1) shl 8) or (at(off + 2) shl 16) or (at(off + 3) shl 24)
        }

        fun writeU32le(out: ByteArray, off: Int, value: Long) {
            val v = value.toInt()
            out[off] = v.toByte()
            out[off + 1] = (v ushr 8).toByte()
            out[off + 2] = (v ushr 16).toByte()
            out[off + 3] = (v ushr 24).toByte()
        }
    }
}
