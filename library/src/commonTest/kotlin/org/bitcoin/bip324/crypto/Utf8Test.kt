package org.bitcoin.bip324.crypto

import org.bitcoin.bip324.bytesToUtf8
import org.bitcoin.bip324.utf8ToBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Utf8Test {
    @Test
    fun runtimeNeutralUtf8CodecHandlesUnicodeAndRejectsMalformedBytes() {
        val value = "bip324 π 🚀"
        assertEquals(value, bytesToUtf8(utf8ToBytes(value)))
        assertFailsWith<IllegalArgumentException> { bytesToUtf8(byteArrayOf(0xc0.toByte(), 0x80.toByte())) }
        assertFailsWith<IllegalArgumentException> { bytesToUtf8(byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte())) }
        assertFailsWith<IllegalArgumentException> {
            bytesToUtf8(byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()))
        }
        assertFailsWith<IllegalArgumentException> { bytesToUtf8(byteArrayOf(0xe2.toByte(), 0x82.toByte())) }
    }
}
