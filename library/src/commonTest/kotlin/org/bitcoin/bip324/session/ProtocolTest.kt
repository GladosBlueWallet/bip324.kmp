package org.bitcoin.bip324.session

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.bitcoin.bip324.AuthenticationError
import org.bitcoin.bip324.ByteDuplex
import org.bitcoin.bip324.MAX_CONTENTS_LEN
import org.bitcoin.bip324.Message
import org.bitcoin.bip324.Networks
import org.bitcoin.bip324.Protocol
import org.bitcoin.bip324.ProtocolClosedError
import org.bitcoin.bip324.ProtocolOptions
import org.bitcoin.bip324.Role
import org.bitcoin.bip324.WireMessageType
import org.bitcoin.bip324.bytesToHex
import org.bitcoin.bip324.pairedByteDuplexes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProtocolTest {
    private suspend fun paired(): Pair<Protocol, Protocol> {
        val (left, right) = pairedByteDuplexes()
        return coroutineScope {
            val a = async { Protocol.connect(left, ProtocolOptions(Role.Initiator, Networks.regtest)) }
            val b = async { Protocol.connect(right, ProtocolOptions(Role.Responder, Networks.regtest)) }
            a.await() to b.await()
        }
    }

    @Test
    fun exchangesPingPongAfterHandshake() {
        runBlocking {
            val (alice, bob) = paired()
            assertEquals(bytesToHex(alice.sessionId), bytesToHex(bob.sessionId))
            val nonce = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
            alice.writeMessage(Message.Ping(nonce))
            val got = bob.readMessage()
            assertTrue(got is Message.Ping)
            assertEquals(bytesToHex(nonce), bytesToHex(got.nonce))
            bob.writeMessage(Message.Pong(got.nonce))
            val pong = alice.readMessage()
            assertTrue(pong is Message.Pong)
        }
    }

    @Test
    fun authenticationFailureClosesAndPermanentlyInvalidatesTheSession() {
        runBlocking {
            val (left, rawRight) = pairedByteDuplexes()
            var tamper = false
            var reads = 0
            var closes = 0
            val right = object : ByteDuplex {
                override suspend fun read(n: Int): ByteArray {
                    val bytes = rawRight.read(n)
                    if (tamper && ++reads == 2 && bytes.isNotEmpty()) {
                        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
                    }
                    return bytes
                }
                override suspend fun write(bytes: ByteArray) = rawRight.write(bytes)
                override suspend fun close() {
                    closes += 1
                    rawRight.close()
                }
            }
            val (alice, bob) = coroutineScope {
                val a = async { Protocol.connect(left, ProtocolOptions(Role.Initiator, Networks.regtest)) }
                val b = async { Protocol.connect(right, ProtocolOptions(Role.Responder, Networks.regtest)) }
                a.await() to b.await()
            }
            tamper = true
            alice.writeMessage(Message.Ping(ByteArray(8)))
            assertFailsWith<AuthenticationError> { bob.readMessage() }
            assertTrue(bob.isClosed)
            assertEquals(1, closes)
            assertFailsWith<ProtocolClosedError> { bob.readMessage() }
            assertFailsWith<ProtocolClosedError> { bob.writeMessage(Message.GetAddr) }
            Unit
        }
    }

    @Test
    fun aFailedWriteClosesTheSessionAfterCipherStateAdvances() {
        runBlocking {
            val (rawLeft, right) = pairedByteDuplexes()
            var failWrites = false
            var closes = 0
            val left = object : ByteDuplex {
                override suspend fun read(n: Int) = rawLeft.read(n)
                override suspend fun write(bytes: ByteArray) {
                    if (failWrites) throw IllegalStateException("socket failed")
                    rawLeft.write(bytes)
                }
                override suspend fun close() {
                    closes += 1
                    rawLeft.close()
                }
            }
            val alice = coroutineScope {
                val a = async { Protocol.connect(left, ProtocolOptions(Role.Initiator, Networks.regtest)) }
                val b = async { Protocol.connect(right, ProtocolOptions(Role.Responder, Networks.regtest)) }
                b.await()
                a.await()
            }
            failWrites = true
            val error = assertFailsWith<IllegalStateException> { alice.writeMessage(Message.GetAddr) }
            assertEquals("socket failed", error.message)
            assertTrue(alice.isClosed)
            assertEquals(1, closes)
        }
    }

    @Test
    fun sessionIdReturnsADefensiveCopy() {
        runBlocking {
            val (alice, _) = paired()
            val original = alice.sessionId
            original.fill(0)
            assertFalse(alice.sessionId.contentEquals(original))
        }
    }

    @Test
    fun closeWakesAnActiveRead() {
        runBlocking {
            val (_, bob) = paired()
            val reading = async {
                try {
                    bob.readMessage()
                    "read"
                } catch (_: Throwable) {
                    "closed"
                }
            }
            bob.close()
            assertEquals("closed", withTimeout(1_000) { reading.await() })
        }
    }

    @Test
    fun concurrentCloseCallsAwaitTheSameTransportTeardown() {
        runBlocking {
            val (rawLeft, right) = pairedByteDuplexes()
            var closeCalls = 0
            val closeGate = CompletableDeferred<Unit>()
            val left = object : ByteDuplex {
                override suspend fun read(n: Int) = rawLeft.read(n)
                override suspend fun write(bytes: ByteArray) = rawLeft.write(bytes)
                override suspend fun close() {
                    closeCalls += 1
                    closeGate.await()
                    rawLeft.close()
                }
            }
            val alice = coroutineScope {
                val a = async { Protocol.connect(left, ProtocolOptions(Role.Initiator, Networks.regtest)) }
                val b = async { Protocol.connect(right, ProtocolOptions(Role.Responder, Networks.regtest)) }
                b.await()
                a.await()
            }
            var secondSettled = false
            val first = async { alice.close() }
            val second = async {
                alice.close()
                secondSettled = true
            }
            kotlinx.coroutines.yield()
            kotlinx.coroutines.yield()
            assertEquals(1, closeCalls)
            assertFalse(secondSettled)
            closeGate.complete(Unit)
            first.await()
            second.await()
            assertTrue(secondSettled)
        }
    }

    @Test
    fun oversizedLocalWritesFailWithoutDestroyingAHealthySession() {
        runBlocking {
            val (alice, bob) = paired()
            val error = assertFailsWith<IllegalArgumentException> {
                alice.writeMessage(
                    Message.Opaque(
                        type = WireMessageType.Short(250),
                        payload = ByteArray(MAX_CONTENTS_LEN + 1),
                    ),
                )
            }
            assertTrue(error.message!!.contains("too large") || error.message!!.contains("exceeds"))
            assertFalse(alice.isClosed)
            val nonce = ByteArray(8) { 7 }
            alice.writeMessage(Message.Ping(nonce))
            val got = bob.readMessage()
            assertTrue(got is Message.Ping)
        }
    }

    @Test
    fun closeDuringAnInFlightWriteDoesNotHang() {
        runBlocking {
            val (rawLeft, right) = pairedByteDuplexes()
            val writeStarted = CompletableDeferred<Unit>()
            val allowWrite = CompletableDeferred<Unit>()
            var holdWrites = false
            val left = object : ByteDuplex {
                override suspend fun read(n: Int) = rawLeft.read(n)
                override suspend fun write(bytes: ByteArray) {
                    if (holdWrites) {
                        writeStarted.complete(Unit)
                        allowWrite.await()
                    }
                    rawLeft.write(bytes)
                }
                override suspend fun close() {
                    rawLeft.close()
                }
            }
            val alice = coroutineScope {
                val a = async { Protocol.connect(left, ProtocolOptions(Role.Initiator, Networks.regtest)) }
                val b = async { Protocol.connect(right, ProtocolOptions(Role.Responder, Networks.regtest)) }
                b.await()
                a.await()
            }
            holdWrites = true
            val writing = async { runCatching { alice.writeMessage(Message.GetAddr) } }
            writeStarted.await()
            val closing = async { alice.close() }
            allowWrite.complete(Unit)
            writing.await()
            closing.await()
            assertTrue(alice.isClosed)
            assertFailsWith<ProtocolClosedError> { alice.writeMessage(Message.GetAddr) }
        }
    }

    @Test
    fun connectTimeoutStillClosesTheDuplex() {
        runBlocking {
            var closes = 0
            val hanging = object : ByteDuplex {
                override suspend fun read(n: Int): ByteArray = awaitCancellation()
                override suspend fun write(bytes: ByteArray) {}
                override suspend fun close() {
                    closes += 1
                }
            }
            val result = withTimeoutOrNull(80) {
                Protocol.connect(hanging, ProtocolOptions(Role.Initiator, Networks.regtest))
            }
            assertEquals(null, result)
            assertEquals(1, closes)
        }
    }
}
