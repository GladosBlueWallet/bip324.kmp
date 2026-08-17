package io.bluewallet.bip324.messages

import io.bluewallet.bip324.BlockValidationError
import io.bluewallet.bip324.Transaction
import io.bluewallet.bip324.TxInput
import io.bluewallet.bip324.TxOutput
import io.bluewallet.bip324.OutPoint
import io.bluewallet.bip324.assertBlockPayload
import io.bluewallet.bip324.bytesToHex
import io.bluewallet.bip324.decodeBlock
import io.bluewallet.bip324.hexToBytes
import io.bluewallet.bip324.transactionId
import io.bluewallet.bip324.transactionMerkleRoot
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BlockValidateTest {
    private val genesisBlockHex =
        "01000000" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
            "29ab5f49ffff001d1dac2b7c" +
            "01" +
            "01000000" +
            "01" +
            "0000000000000000000000000000000000000000000000000000000000000000" +
            "ffffffff" +
            "4d" +
            "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73" +
            "ffffffff" +
            "01" +
            "00f2052a01000000" +
            "43" +
            "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac" +
            "00000000"

    @Test
    fun knownBitcoinGenesisBlockValidatesTxidMerkleRootAndHeaderHash() {
        val block = decodeBlock(hexToBytes(genesisBlockHex))
        val expectedHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        val expectedTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        assertEquals(expectedTxid, bytesToHex(transactionId(block.transactions[0]).reversedArray()))
        assertEquals(bytesToHex(block.header.merkleRoot), bytesToHex(transactionMerkleRoot(block.transactions)))
        assertBlockPayload(block, expectedHash)
    }

    @Test
    fun transactionIdsExcludeWitnessAndEmptyBlocksHaveNoMerkleRoot() {
        val base = Transaction(
            version = 2u,
            inputs = listOf(
                TxInput(
                    previousOutput = OutPoint(ByteArray(32) { 1 }, 0u),
                    scriptSig = byteArrayOf(0x51),
                    sequence = 0xffff_ffffu,
                ),
            ),
            outputs = listOf(TxOutput(1, byteArrayOf(0x51))),
            lockTime = 0u,
        )
        val witnessed = Transaction(
            version = base.version,
            inputs = base.inputs.map { input ->
                TxInput(input.previousOutput, input.scriptSig, input.sequence, listOf(byteArrayOf(1, 2, 3)))
            },
            outputs = base.outputs,
            lockTime = base.lockTime,
        )
        assertContentEquals(transactionId(base), transactionId(witnessed))
        assertTrue(
            assertFailsWith<BlockValidationError> { transactionMerkleRoot(emptyList()) }
                .message!!.contains("block contains no transactions"),
        )
    }

    @Test
    fun validOddWidthMerkleLevelsArePaddedButExplicitDuplicatePairsAreRejected() {
        val genesis = decodeBlock(hexToBytes(genesisBlockHex))
        val first = genesis.transactions[0]
        val second = Transaction(first.version, first.inputs, first.outputs, 1u)
        val third = Transaction(first.version, first.inputs, first.outputs, 2u)
        transactionMerkleRoot(listOf(first, second, third))
        assertTrue(
            assertFailsWith<BlockValidationError> {
                transactionMerkleRoot(listOf(first, second, third, third))
            }.message!!.contains("mutated merkle tree"),
        )
    }
}
