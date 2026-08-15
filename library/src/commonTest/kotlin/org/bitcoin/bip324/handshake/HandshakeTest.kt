package org.bitcoin.bip324.handshake

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.bitcoin.bip324.ByteDuplex
import org.bitcoin.bip324.HandshakeOptions
import org.bitcoin.bip324.Networks
import org.bitcoin.bip324.Role
import org.bitcoin.bip324.V1HandshakeResult
import org.bitcoin.bip324.V2HandshakeResult
import org.bitcoin.bip324.bytesToHex
import org.bitcoin.bip324.ellswiftCreate
import org.bitcoin.bip324.pairedByteDuplexes
import org.bitcoin.bip324.performHandshake
import org.bitcoin.bip324.utf8ToBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HandshakeTest {
    @Test
    fun initiatorAndResponderCompleteWithMatchingSessionIds() {
        runBlocking {
            val (left, right) = pairedByteDuplexes()
            val (a, b) = coroutineScope {
                val leftJob = async {
                    performHandshake(left, HandshakeOptions(Role.Initiator, Networks.mainnet))
                }
                val rightJob = async {
                    performHandshake(right, HandshakeOptions(Role.Responder, Networks.mainnet))
                }
                leftJob.await() to rightJob.await()
            }
            assertTrue(a is V2HandshakeResult && b is V2HandshakeResult)
            assertEquals(bytesToHex(a.session.sessionId), bytesToHex(b.session.sessionId))
        }
    }

    @Test
    fun handshakeWorksWithOptionalGarbage() {
        runBlocking {
            val (left, right) = pairedByteDuplexes()
            val (a, b) = coroutineScope {
                val leftJob = async {
                    performHandshake(
                        left,
                        HandshakeOptions(Role.Initiator, Networks.testnet3, garbage = byteArrayOf(1, 2, 3, 4)),
                    )
                }
                val rightJob = async {
                    performHandshake(
                        right,
                        HandshakeOptions(Role.Responder, Networks.testnet3, garbage = byteArrayOf(9, 8, 7)),
                    )
                }
                leftJob.await() to rightJob.await()
            }
            assertTrue(a is V2HandshakeResult && b is V2HandshakeResult)
            assertEquals(bytesToHex(a.session.sessionId), bytesToHex(b.session.sessionId))
        }
    }

    @Test
    fun returnsConsumedBytesWhenTheResponderDetectsV1() {
        runBlocking {
            val prefix = Networks.mainnet.magic + utf8ToBytes("version") + ByteArray(5)
            var offset = 0
            val duplex = object : ByteDuplex {
                override suspend fun read(n: Int): ByteArray {
                    val chunk = prefix.copyOfRange(offset, minOf(offset + n, prefix.size))
                    offset += chunk.size
                    return chunk
                }
                override suspend fun write(bytes: ByteArray) {
                    throw IllegalStateException("responder must not write before handing v1 back")
                }
                override suspend fun close() {}
            }
            val result = performHandshake(duplex, HandshakeOptions(Role.Responder, Networks.mainnet))
            assertTrue(result is V1HandshakeResult)
            assertTrue(result.buffered.contentEquals(prefix))
        }
    }

    @Test
    fun responderSendsItsKeyAsSoonAsV2IsDistinguishable() {
        runBlocking {
            val (rawInitiator, rawResponder) = pairedByteDuplexes()
            var keyPair = ellswiftCreate()
            while (keyPair.publicKey[0] == Networks.mainnet.magic[0]) {
                keyPair = ellswiftCreate()
            }
            val responderWrote = kotlinx.coroutines.CompletableDeferred<Unit>()
            var firstWrite = true
            val initiator = object : ByteDuplex {
                override suspend fun read(n: Int) = rawInitiator.read(n)
                override suspend fun write(bytes: ByteArray) {
                    if (!firstWrite) return rawInitiator.write(bytes)
                    firstWrite = false
                    rawInitiator.write(bytes.copyOf(1))
                    responderWrote.await()
                    rawInitiator.write(bytes.copyOfRange(1, bytes.size))
                }
                override suspend fun close() = rawInitiator.close()
            }
            val responder = object : ByteDuplex {
                override suspend fun read(n: Int) = rawResponder.read(n)
                override suspend fun write(bytes: ByteArray) {
                    responderWrote.complete(Unit)
                    rawResponder.write(bytes)
                }
                override suspend fun close() = rawResponder.close()
            }
            val (a, b) = coroutineScope {
                val leftJob = async {
                    performHandshake(
                        initiator,
                        HandshakeOptions(Role.Initiator, Networks.mainnet, createKeyPair = { keyPair }),
                    )
                }
                val rightJob = async {
                    performHandshake(responder, HandshakeOptions(Role.Responder, Networks.mainnet))
                }
                leftJob.await() to rightJob.await()
            }
            assertEquals("v2", a.transport)
            assertEquals("v2", b.transport)
        }
    }
}
