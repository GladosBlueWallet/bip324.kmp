package org.bitcoin.bip324.messages

import org.bitcoin.bip324.PayloadReader
import org.bitcoin.bip324.PayloadWriter
import org.bitcoin.bip324.bytesToHex
import org.bitcoin.bip324.hexToBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BinaryTest {
    @Test
    fun compactSizeVectors() {
        val vectors = listOf(
            0uL to "00",
            252uL to "fc",
            253uL to "fdfd00",
            65_535uL to "fdffff",
            65_536uL to "fe00000100",
            4_294_967_296uL to "ff0000000001000000",
        )
        for ((value, hex) in vectors) {
            val writer = PayloadWriter()
            writer.compactSize(value)
            assertEquals(hex, bytesToHex(writer.finish()), "$value")
            val reader = PayloadReader(hexToBytes(hex))
            assertEquals(value, reader.compactSizeULong())
            reader.finish()
        }
    }

    @Test
    fun rejectsNonCanonicalAndTruncatedEncodings() {
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                PayloadReader(hexToBytes("fdfc00")).compactSizeULong()
            }.message!!.contains("non-canonical"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                PayloadReader(hexToBytes("feffff0000")).compactSizeULong()
            }.message!!.contains("non-canonical"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                PayloadReader(hexToBytes("ffffffffff00000000")).compactSizeULong()
            }.message!!.contains("non-canonical"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                PayloadReader(hexToBytes("fd")).compactSizeULong()
            }.message!!.contains("truncated"),
        )
    }

    @Test
    fun numberConversionRejectsValuesAboveIntRange() {
        val reader = PayloadReader(hexToBytes("ff" + "ff".repeat(8)))
        assertTrue(
            assertFailsWith<IllegalArgumentException> { reader.compactSize() }
                .message!!.contains("safe integer"),
        )
    }
}
