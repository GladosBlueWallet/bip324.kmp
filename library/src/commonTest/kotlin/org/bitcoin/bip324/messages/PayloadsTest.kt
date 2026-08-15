package org.bitcoin.bip324.messages

import org.bitcoin.bip324.AddrPayload
import org.bitcoin.bip324.AddrV2Payload
import org.bitcoin.bip324.GetHeadersPayload
import org.bitcoin.bip324.InventoryPayload
import org.bitcoin.bip324.InventoryVector
import org.bitcoin.bip324.Message
import org.bitcoin.bip324.NetworkAddress
import org.bitcoin.bip324.NetworkAddressV2
import org.bitcoin.bip324.TimedNetworkAddress
import org.bitcoin.bip324.VersionPayload
import org.bitcoin.bip324.WitnessStack
import org.bitcoin.bip324.bytesToHex
import org.bitcoin.bip324.decodeMessage
import org.bitcoin.bip324.encodeMessage
import org.bitcoin.bip324.hexToBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PayloadsTest {
    private val ipv4Loopback = hexToBytes("00000000000000000000ffff7f000001")
    private val genesisHeader = listOf(
        "01000000",
        "00".repeat(32),
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        "29ab5f49",
        "ffff001d",
        "1dac2b7c",
    ).joinToString("")
    private val genesisTx = listOf(
        "01000000",
        "01",
        "00".repeat(32),
        "ffffffff",
        "4d",
        "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
        "ffffffff",
        "01",
        "00f2052a01000000",
        "43",
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
        "00000000",
    ).joinToString("")

    @Test
    fun versionMatchesAFixedWireFixture() {
        val payload = VersionPayload(
            version = 70_016,
            services = 1uL,
            timestamp = 0,
            receiver = NetworkAddress(1uL, ipv4Loopback, 8333),
            sender = NetworkAddress(0uL, ByteArray(16), 0),
            nonce = 0x0102_0304_0506_0708uL,
            userAgent = "/bip324:0.1/",
            startHeight = 100,
            relay = false,
        )
        val expectedPayload = listOf(
            "80110100",
            "0100000000000000",
            "0000000000000000",
            "0100000000000000",
            bytesToHex(ipv4Loopback),
            "208d",
            "0000000000000000",
            "00".repeat(16),
            "0000",
            "0807060504030201",
            "0c2f6269703332343a302e312f",
            "64000000",
            "00",
        ).joinToString("")
        val wire = encodeMessage(Message.Version(payload))
        assertEquals(expectedPayload, bytesToHex(wire.copyOfRange(13, wire.size)))
        val decoded = decodeMessage(wire)
        assertTrue(decoded is Message.Version)
        assertEquals(payload.userAgent, decoded.payload.userAgent)
        assertEquals(payload.nonce, decoded.payload.nonce)
        assertEquals(false, decoded.payload.relay)
    }

    @Test
    fun versionWithoutARelayByteDefaultsToBip37RelayEnabled() {
        val withRelay = encodeMessage(
            Message.Version(
                VersionPayload(
                    version = 70_016,
                    services = 0uL,
                    timestamp = 0,
                    receiver = NetworkAddress(0uL, ByteArray(16), 0),
                    sender = NetworkAddress(0uL, ByteArray(16), 0),
                    nonce = 0uL,
                    userAgent = "/",
                    startHeight = 0,
                    relay = false,
                ),
            ),
        )
        val decoded = decodeMessage(withRelay.copyOf(withRelay.size - 1))
        assertTrue(decoded is Message.Version)
        assertEquals(true, decoded.payload.relay)
    }

    @Test
    fun addrAndAddrv2EncodeNetworkAddresses() {
        val addr = Message.Addr(
            AddrPayload(
                listOf(TimedNetworkAddress(0x0102_0304u, 1uL, ipv4Loopback, 8333)),
            ),
        )
        val addrWire = encodeMessage(addr)
        assertEquals(
            "01" + "01" + "04030201" + "0100000000000000" + bytesToHex(ipv4Loopback) + "208d",
            bytesToHex(addrWire),
        )
        val decodedAddr = decodeMessage(addrWire)
        assertTrue(decodedAddr is Message.Addr)
        assertEquals(1, decodedAddr.payload.addresses.size)
        assertEquals(8333, decodedAddr.payload.addresses[0].port)

        val addrv2 = Message.AddrV2(
            AddrV2Payload(
                listOf(NetworkAddressV2(0x0102_0304u, 2048uL, 1, byteArrayOf(127, 0, 0, 1), 8333)),
            ),
        )
        val addrv2Wire = encodeMessage(addrv2)
        assertEquals("1c0104030201fd000801047f000001208d", bytesToHex(addrv2Wire))
        assertTrue(decodeMessage(addrv2Wire) is Message.AddrV2)
    }

    @Test
    fun addrv2KeepsUnknownNetworkIdsAndOnlyRejectsKnownIdLengthMismatches() {
        val unknownFuture = hexToBytes("1c01000000000008110200000000000000000000000000000000208d")
        val decodedFuture = decodeMessage(unknownFuture)
        assertTrue(decodedFuture is Message.AddrV2)
        assertEquals(8, decodedFuture.payload.addresses[0].networkId)
        assertTrue(encodeMessage(decodedFuture).contentEquals(unknownFuture))

        val reservedZero = hexToBytes("1c0100000000000001aa208d")
        val decodedZero = decodeMessage(reservedZero)
        assertTrue(decodedZero is Message.AddrV2)
        assertEquals(0, decodedZero.payload.addresses[0].networkId)

        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                decodeMessage(hexToBytes("1c01000000000001037f0001208d"))
            }.message!!.contains("address length"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                decodeMessage(hexToBytes("1c01000000000007110200000000000000000000000000000000208d"))
            }.message!!.contains("address length"),
        )
    }

    @Test
    fun getheadersHeadersAndInventoryVectorsRoundtrip() {
        val getheaders = Message.GetHeaders(
            GetHeadersPayload(70_016, listOf(ByteArray(32) { 0x11 }), ByteArray(32)),
        )
        val round = decodeMessage(encodeMessage(getheaders))
        assertTrue(round is Message.GetHeaders)
        assertEquals(70_016, round.payload.version)

        val headersWire = hexToBytes("0d01$genesisHeader" + "00")
        val headers = decodeMessage(headersWire)
        assertTrue(headers is Message.Headers)
        assertEquals(1, headers.payload.headers.size)
        assertEquals(1_231_006_505u, headers.payload.headers[0].timestamp)
        assertTrue(encodeMessage(headers).contentEquals(headersWire))

        val inv = Message.Inv(InventoryPayload(listOf(InventoryVector(2u, ByteArray(32) { 0x22 }))))
        assertTrue(decodeMessage(encodeMessage(inv)) is Message.Inv)
        assertTrue(decodeMessage(encodeMessage(Message.GetData(inv.payload))) is Message.GetData)
        assertTrue(decodeMessage(encodeMessage(Message.NotFound(inv.payload))) is Message.NotFound)
    }

    @Test
    fun decodesAndReEncodesTheRealGenesisTransactionAndBlock() {
        val txWire = hexToBytes("15$genesisTx")
        val tx = decodeMessage(txWire)
        assertTrue(tx is Message.Tx)
        assertEquals(1, tx.payload.inputs.size)
        assertEquals(5_000_000_000L, tx.payload.outputs[0].value)
        assertTrue(encodeMessage(tx).contentEquals(txWire))

        val blockWire = hexToBytes("02$genesisHeader" + "01$genesisTx")
        val block = decodeMessage(blockWire)
        assertTrue(block is Message.Block)
        assertEquals(1, block.payload.transactions.size)
        assertEquals(2_083_236_893u, block.payload.header.nonce)
        assertTrue(encodeMessage(block).contentEquals(blockWire))
    }

    @Test
    fun preservesSegregatedWitnessTransactionData() {
        val witnessTx = listOf(
            "02000000", "0001", "01", "11".repeat(32), "00000000", "00", "ffffffff",
            "01", "0100000000000000", "01", "51", "02", "01aa", "02bbcc", "00000000",
        ).joinToString("")
        val wire = hexToBytes("15$witnessTx")
        val decoded = decodeMessage(wire)
        assertTrue(decoded is Message.Tx)
        val items = decoded.payload.inputs[0].witness!!.toList()
        assertEquals(2, items.size)
        assertTrue(items[0].contentEquals(byteArrayOf(0xaa.toByte())))
        assertTrue(items[1].contentEquals(byteArrayOf(0xbb.toByte(), 0xcc.toByte())))
        assertTrue(encodeMessage(decoded).contentEquals(wire))
    }

    @Test
    fun preservesUnsignedTransactionVersionsAndSignedOutputValues() {
        val unusual = genesisTx.replace(Regex("^01000000"), "ffffffff")
            .replace("00f2052a01000000", "ffffffffffffffff")
        val wire = hexToBytes("15$unusual")
        val decoded = decodeMessage(wire)
        assertTrue(decoded is Message.Tx)
        assertEquals(0xffff_ffffu, decoded.payload.version)
        assertEquals(-1L, decoded.payload.outputs[0].value)
        assertTrue(encodeMessage(decoded).contentEquals(wire))
    }

    @Test
    fun rejectsMalformedTypedPayloadsAndTrailingData() {
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                decodeMessage(hexToBytes("1c01000000000001037f0001208d"))
            }.message!!.contains("address length"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                decodeMessage(hexToBytes("0d01$genesisHeader" + "01"))
            }.message!!.contains("transaction count"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                decodeMessage(hexToBytes("15$genesisTx" + "00"))
            }.message!!.contains("trailing"),
        )
        val superfluousWitness = listOf(
            "15", "02000000", "0001", "01", "11".repeat(32), "00000000", "00", "ffffffff",
            "01", "0100000000000000", "01", "51", "00", "00000000",
        ).joinToString("")
        assertTrue(
            assertFailsWith<IllegalArgumentException> { decodeMessage(hexToBytes(superfluousWitness)) }
                .message!!.contains("superfluous"),
        )
        val manyWitnessItems = listOf(
            "15", "02000000", "0001", "01", "11".repeat(32), "00000000", "00", "ffffffff",
            "01", "0100000000000000", "01", "51",
            "fea1860100", "00".repeat(100_001), "00000000",
        ).joinToString("")
        val manyWitnessDecoded = decodeMessage(hexToBytes(manyWitnessItems))
        assertTrue(manyWitnessDecoded is Message.Tx)
        val witness = manyWitnessDecoded.payload.inputs[0].witness
        assertTrue(witness is WitnessStack)
        assertEquals(100_001, witness.length)
        assertTrue(encodeMessage(manyWitnessDecoded).contentEquals(hexToBytes(manyWitnessItems)))

        val impossibleWitnessCount = listOf(
            "15", "02000000", "0001", "01", "11".repeat(32), "00000000", "00", "ffffffff",
            "01", "0100000000000000", "01", "51", "feffffff00",
        ).joinToString("")
        assertTrue(
            assertFailsWith<IllegalArgumentException> { decodeMessage(hexToBytes(impossibleWitnessCount)) }
                .message!!.contains("remaining payload"),
        )
        val excessiveOutputs = listOf(
            "15", "02000000", "01", "11".repeat(32), "00000000", "00", "ffffffff",
            "fe49e80100", "000000000000000000".repeat(125_001), "00000000",
        ).joinToString("")
        assertTrue(
            assertFailsWith<IllegalArgumentException> { decodeMessage(hexToBytes(excessiveOutputs)) }
                .message!!.contains("allocation limit"),
        )
        val oneInput = "01" + "11".repeat(32) + "0000000000ffffffff"
        val manyOutputsTx = "02000000$oneInput" + "fd25f4" + "000000000000000000".repeat(62_501) + "00000000"
        val aggregateOutputsBlock = "02" + "00".repeat(80) + "02$manyOutputsTx$manyOutputsTx"
        assertTrue(
            assertFailsWith<IllegalArgumentException> { decodeMessage(hexToBytes(aggregateOutputsBlock)) }
                .message!!.contains("aggregate allocation"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                encodeMessage(
                    Message.Version(
                        VersionPayload(
                            version = 70_016,
                            services = 0uL,
                            timestamp = 0,
                            receiver = NetworkAddress(0uL, ByteArray(16), 0),
                            sender = NetworkAddress(0uL, ByteArray(16), 0),
                            nonce = 0uL,
                            userAgent = "x".repeat(257),
                            startHeight = 0,
                        ),
                    ),
                )
            }.message!!.contains("user agent"),
        )
    }
}
