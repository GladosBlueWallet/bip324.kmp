package io.bluewallet.bip324.messages

import io.bluewallet.bip324.Message
import io.bluewallet.bip324.Networks
import io.bluewallet.bip324.SHORT_ID_TO_COMMAND
import io.bluewallet.bip324.SHORT_MESSAGE_IDS
import io.bluewallet.bip324.WireMessageType
import io.bluewallet.bip324.bytesToHex
import io.bluewallet.bip324.concatBytes
import io.bluewallet.bip324.decodeMessage
import io.bluewallet.bip324.encodeMessage
import io.bluewallet.bip324.utf8ToBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CodecTest {
    @Test
    fun pingUsesShortId18() {
        val nonce = ByteArray(8) { 0xab.toByte() }
        val encoded = encodeMessage(Message.Ping(nonce))
        assertEquals(18, encoded[0].toInt() and 0xff)
        assertEquals(9, encoded.size)
        val decoded = decodeMessage(encoded)
        assertTrue(decoded is Message.Ping)
        assertEquals(bytesToHex(nonce), bytesToHex(decoded.nonce))
    }

    @Test
    fun getaddrUsesLongForm() {
        val encoded = encodeMessage(Message.GetAddr)
        assertEquals(0, encoded[0].toInt())
    }

    @Test
    fun acceptsLongFormAliasesForCommandsWithShortIds() {
        val longPing = ByteArray(21)
        utf8ToBytes("ping").copyInto(longPing, 1)
        longPing.fill(0xaa.toByte(), 13)
        val decoded = decodeMessage(longPing)
        assertTrue(decoded is Message.Ping)
        assertTrue(decoded.nonce.contentEquals(ByteArray(8) { 0xaa.toByte() }))
    }

    @Test
    fun roundtripsUnknownShortIdsWithoutInventingACommandName() {
        val wire = byteArrayOf(250.toByte(), 1, 2, 3)
        val decoded = decodeMessage(wire)
        assertEquals(Message.Opaque(WireMessageType.Short(250), byteArrayOf(1, 2, 3)), decoded)
        assertTrue(encodeMessage(decoded).contentEquals(wire))
    }

    @Test
    fun keepsCurrentlyUndefinedId29Opaque() {
        val decoded = decodeMessage(byteArrayOf(29))
        assertEquals(Message.Opaque(WireMessageType.Short(29), ByteArray(0)), decoded)
    }

    @Test
    fun rejectsMalformedLongFormCommandPaddingAndNonPrintableAscii() {
        val embeddedNul = concatBytes(byteArrayOf(0), byteArrayOf(0x70, 0, 0x69), ByteArray(9))
        val control = concatBytes(byteArrayOf(0, 0x1f), ByteArray(11))
        val nonAscii = concatBytes(byteArrayOf(0, 0x80.toByte()), ByteArray(11))
        assertTrue(assertFailsWith<IllegalArgumentException> { decodeMessage(embeddedNul) }.message!!.contains("padding"))
        assertTrue(assertFailsWith<IllegalArgumentException> { decodeMessage(control) }.message!!.contains("printable ASCII"))
        assertTrue(assertFailsWith<IllegalArgumentException> { decodeMessage(nonAscii) }.message!!.contains("printable ASCII"))
        assertTrue(assertFailsWith<IllegalArgumentException> { decodeMessage(byteArrayOf(0, 0x70)) }.message!!.contains("truncated"))
    }

    @Test
    fun rejectsPayloadsOnPayloadlessCommands() {
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                decodeMessage(concatBytes(encodeMessage(Message.Verack), byteArrayOf(1)))
            }.message!!.contains("verack payload must be empty"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                decodeMessage(concatBytes(encodeMessage(Message.GetAddr), byteArrayOf(1)))
            }.message!!.contains("getaddr payload must be empty"),
        )
    }

    @Test
    fun exportedProtocolConstantsCannotMutateInternalFramingState() {
        assertEquals(18, SHORT_MESSAGE_IDS.getValue("ping"))
        assertEquals("ping", SHORT_ID_TO_COMMAND.getValue(18))
        val magic = Networks.mainnet.magic
        magic.fill(0)
        assertEquals("f9beb4d9", bytesToHex(Networks.mainnet.magic))
    }
}
