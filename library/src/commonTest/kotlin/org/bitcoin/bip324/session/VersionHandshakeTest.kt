package org.bitcoin.bip324.session

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.bitcoin.bip324.Message
import org.bitcoin.bip324.NetworkAddress
import org.bitcoin.bip324.Networks
import org.bitcoin.bip324.Protocol
import org.bitcoin.bip324.ProtocolOptions
import org.bitcoin.bip324.Role
import org.bitcoin.bip324.VersionHandshakeOptions
import org.bitcoin.bip324.VersionPayload
import org.bitcoin.bip324.answerPing
import org.bitcoin.bip324.completeVersionHandshake
import org.bitcoin.bip324.pairedByteDuplexes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class VersionHandshakeTest {
    private suspend fun pairedProtocols(): Pair<Protocol, Protocol> {
        val (a, b) = pairedByteDuplexes()
        return coroutineScope {
            val left = async { Protocol.connect(a, ProtocolOptions(Role.Initiator, Networks.regtest)) }
            val right = async { Protocol.connect(b, ProtocolOptions(Role.Responder, Networks.regtest)) }
            left.await() to right.await()
        }
    }

    @Test
    fun advertisesAppIdentityAndReturnsPeerServicesStartHeight() {
        runBlocking {
            val (alice, bob) = pairedProtocols()
            try {
                val bobSide = async {
                    val inbound = bob.readMessage()
                    assertTrue(inbound is Message.Version)
                    assertEquals("/wallet:3.1.4/", inbound.payload.userAgent)
                    bob.writeMessage(
                        Message.Version(
                            VersionPayload(
                                version = 70_016,
                                services = 2048uL,
                                timestamp = 0,
                                receiver = NetworkAddress(0uL, ByteArray(16), 18444),
                                sender = NetworkAddress(0uL, ByteArray(16), 0),
                                nonce = 1uL,
                                userAgent = "/peer:0/",
                                startHeight = 99,
                                relay = false,
                            ),
                        ),
                    )
                    bob.writeMessage(Message.Verack)
                    while (true) {
                        if (bob.readMessage() is Message.Verack) return@async
                    }
                }
                val peer = completeVersionHandshake(
                    alice,
                    VersionHandshakeOptions(port = 18444, name = "wallet", version = "3.1.4", sendAddrV2 = false),
                )
                bobSide.await()
                assertEquals(2048uL, peer.services)
                assertEquals(99, peer.startHeight)
            } finally {
                alice.close()
                bob.close()
            }
        }
    }

    @Test
    fun ignoresADuplicateVersionInsteadOfSendingASecondVerack() {
        runBlocking {
            val (alice, bob) = pairedProtocols()
            try {
                val peerVersion = Message.Version(
                    VersionPayload(
                        version = 70_016,
                        services = 1uL,
                        timestamp = 0,
                        receiver = NetworkAddress(0uL, ByteArray(16), 18444),
                        sender = NetworkAddress(0uL, ByteArray(16), 0),
                        nonce = 1uL,
                        userAgent = "/peer:0/",
                        startHeight = 1,
                        relay = false,
                    ),
                )
                val bobSide = async {
                    assertTrue(bob.readMessage() is Message.Version)
                    bob.writeMessage(peerVersion)
                    bob.writeMessage(peerVersion)
                    bob.writeMessage(Message.Verack)
                    val first = bob.readMessage()
                    assertTrue(first is Message.Verack)
                    assertFailsWith<Throwable> { bob.readMessage() }
                    Unit
                }
                val peer = completeVersionHandshake(
                    alice,
                    VersionHandshakeOptions(port = 18444, name = "wallet", version = "1", sendAddrV2 = false),
                )
                assertEquals(1uL, peer.services)
                assertEquals(1, peer.startHeight)
                alice.close()
                bobSide.await()
            } finally {
                alice.close()
                bob.close()
            }
        }
    }

    @Test
    fun givesUpWhenThePeerNeverSendsVersionOrVerack() {
        runBlocking {
            val (alice, bob) = pairedProtocols()
            try {
                val bobSide = async {
                    assertTrue(bob.readMessage() is Message.Version)
                    repeat(40) { bob.writeMessage(Message.GetAddr) }
                }
                val error = assertFailsWith<IllegalStateException> {
                    completeVersionHandshake(
                        alice,
                        VersionHandshakeOptions(port = 18444, name = "wallet", version = "1", sendAddrV2 = false),
                    )
                }
                assertTrue(error.message!!.contains("version handshake"))
                bobSide.await()
            } finally {
                alice.close()
                bob.close()
            }
        }
    }

    @Test
    fun repliesToPingWithAMatchingPong() {
        runBlocking {
            val (alice, bob) = pairedProtocols()
            try {
                coroutineScope {
                    val a = async {
                        completeVersionHandshake(
                            alice,
                            VersionHandshakeOptions(port = 18444, name = "a", version = "0", sendAddrV2 = false),
                        )
                    }
                    val b = async {
                        completeVersionHandshake(
                            bob,
                            VersionHandshakeOptions(port = 18444, name = "b", version = "0", sendAddrV2 = false),
                        )
                    }
                    a.await()
                    b.await()
                }
                val nonce = ByteArray(8) { 3 }
                val pongWait = async { bob.readMessage() }
                bob.writeMessage(Message.Ping(nonce))
                val ping = alice.readMessage()
                assertTrue(ping is Message.Ping)
                answerPing(alice, ping)
                val pong = pongWait.await()
                assertTrue(pong is Message.Pong)
                assertTrue(pong.nonce.contentEquals(nonce))
            } finally {
                alice.close()
                bob.close()
            }
        }
    }
}
