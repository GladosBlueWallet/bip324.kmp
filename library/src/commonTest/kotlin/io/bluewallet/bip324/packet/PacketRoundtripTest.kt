package io.bluewallet.bip324.packet

import kotlinx.coroutines.runBlocking
import io.bluewallet.bip324.AuthenticationError
import io.bluewallet.bip324.Networks
import io.bluewallet.bip324.bytesToHex
import io.bluewallet.bip324.decodePacket
import io.bluewallet.bip324.deriveSessionKeys
import io.bluewallet.bip324.ellswiftCreate
import io.bluewallet.bip324.encodePacket
import io.bluewallet.bip324.helpers.BufferReader
import io.bluewallet.bip324.helpers.FragmentingReader
import io.bluewallet.bip324.v2Ecdh
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PacketRoundtripTest {
    @Test
    fun encodeThenDecodeRecoversContents() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            assertEquals(bytesToHex(secretA), bytesToHex(secretB))
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val contents = byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte())
            val packet = encodePacket(send, contents)
            val got = decodePacket(recv, BufferReader(packet))
            assertEquals(bytesToHex(contents), bytesToHex(got))
            Unit
        }
    }

    @Test
    fun decodeAcceptsFragmentedStreamReads() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val contents = byteArrayOf(1, 2, 3, 4, 5)
            val packet = encodePacket(send, contents)
            val got = decodePacket(recv, FragmentingReader(packet, 1))
            assertContentEquals(contents, got)
        }
    }

    @Test
    fun skipsAuthenticatedDecoysAndAppliesAadOnlyToTheFirstPacket() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val aad = byteArrayOf(9, 8, 7)
            val decoy = encodePacket(send, byteArrayOf(0xaa.toByte()), aad = aad, ignore = true)
            val real = encodePacket(send, byteArrayOf(0xbb.toByte()))
            val stream = decoy + real
            val reader = FragmentingReader(stream, 2)
            val got = decodePacket(recv, reader, io.bluewallet.bip324.DecodePacketOpts(aad = aad))
            assertContentEquals(byteArrayOf(0xbb.toByte()), got)
            assertEquals(stream.size, reader.offset)
        }
    }

    @Test
    fun rejectsARunOfDecoysAboveTheConsecutiveIgnoreCap() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val decoy = encodePacket(send, byteArrayOf(0xaa.toByte()), ignore = true)
            val extra = encodePacket(send, byteArrayOf(0xbb.toByte()), ignore = true)
            val real = encodePacket(send, byteArrayOf(0xcc.toByte()))
            val stream = decoy + extra + real
            val error = assertFailsWith<IllegalStateException> {
                decodePacket(recv, BufferReader(stream), io.bluewallet.bip324.DecodePacketOpts(maxIgnorePackets = 1))
            }
            assertTrue(error.message!!.contains("decoy"))
            assertFailsWith<IllegalStateException> { recv.recvL.decrypt(ByteArray(3)) }
            Unit
        }
    }

    @Test
    fun roundtripsAcrossThe224PacketRekeyBoundaryForBothCiphers() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val packets = ArrayList<ByteArray>(300)
            for (i in 0 until 300) {
                packets.add(encodePacket(send, byteArrayOf((i and 0xff).toByte(), ((i ushr 8) and 0xff).toByte(), 0x42)))
            }
            val stream = io.bluewallet.bip324.concatBytes(*packets.toTypedArray())
            val reader = BufferReader(stream)
            for (i in 0 until 300) {
                val got = decodePacket(recv, reader)
                assertContentEquals(byteArrayOf((i and 0xff).toByte(), ((i ushr 8) and 0xff).toByte(), 0x42), got)
            }
            assertEquals(stream.size, reader.offset)
        }
    }

    @Test
    fun rejectsOversizedPacketContentsLengthBeforeAllocation() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val packet = encodePacket(send, byteArrayOf(1, 2, 3))
            val error = assertFailsWith<IllegalStateException> {
                decodePacket(recv, BufferReader(packet), io.bluewallet.bip324.DecodePacketOpts(maxContentsLen = 2))
            }
            assertTrue(error.message!!.contains("exceeds max 2"))
            assertFailsWith<IllegalStateException> { recv.recvL.decrypt(ByteArray(3)) }
            Unit
        }
    }

    @Test
    fun rejectsTamperedAuthenticatedCiphertext() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val packet = encodePacket(send, byteArrayOf(1, 2, 3))
            packet[packet.size - 1] = (packet[packet.size - 1].toInt() xor 1).toByte()
            assertFailsWith<AuthenticationError> { decodePacket(recv, BufferReader(packet)) }
            Unit
        }
    }

    @Test
    fun decodeFailureCanLeaveSendKeysIntact() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
            val send = deriveSessionKeys(secretA, Networks.mainnet.magic, true)
            val recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false)
            val packet = encodePacket(send, byteArrayOf(1, 2, 3))
            packet[packet.size - 1] = (packet[packet.size - 1].toInt() xor 1).toByte()
            assertFailsWith<AuthenticationError> {
                decodePacket(
                    recv,
                    BufferReader(packet),
                    io.bluewallet.bip324.DecodePacketOpts(destroyOnError = false),
                )
            }
            val next = encodePacket(send, byteArrayOf(4, 5, 6))
            val got = decodePacket(
                recv,
                BufferReader(next),
                io.bluewallet.bip324.DecodePacketOpts(destroyOnError = false),
            )
            assertContentEquals(byteArrayOf(4, 5, 6), got)
        }
    }

    @Test
    fun rejectsTruncatedPacketStreams() {
        runBlocking {
            val a = ellswiftCreate()
            val b = ellswiftCreate()
            val secret = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
            val send = deriveSessionKeys(secret, Networks.mainnet.magic, true)
            val packet = encodePacket(send, byteArrayOf(1, 2, 3))
            val receiver = deriveSessionKeys(secret, Networks.mainnet.magic, false)
            val reader = object : io.bluewallet.bip324.ByteReader {
                var offset = 0
                override suspend fun read(n: Int): ByteArray {
                    val end = minOf(offset + n, packet.size - 1)
                    val chunk = packet.copyOfRange(offset, maxOf(offset, end))
                    offset += chunk.size
                    return chunk
                }
            }
            val error = assertFailsWith<IllegalStateException> { decodePacket(receiver, reader) }
            assertTrue(error.message!!.contains("unexpected EOF"))
            assertFailsWith<IllegalStateException> { receiver.recvL.decrypt(ByteArray(3)) }
            Unit
        }
    }
}
