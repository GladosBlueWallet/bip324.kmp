package org.bitcoin.bip324

private fun transactionWithoutWitness(transaction: Transaction): Transaction =
    Transaction(
        version = transaction.version,
        inputs = transaction.inputs.map { input ->
            TxInput(
                previousOutput = input.previousOutput,
                scriptSig = input.scriptSig,
                sequence = input.sequence,
                witness = null,
            )
        },
        outputs = transaction.outputs,
        lockTime = transaction.lockTime,
    )

/** Bitcoin txid (double-SHA256 of the non-witness serialization), internal order. */
fun transactionId(transaction: Transaction): ByteArray =
    sha256d(encodeTransaction(transactionWithoutWitness(transaction)))

/**
 * Transaction merkle root (internal byte order).
 * Rejects empty blocks and CVE-2012-2458-style explicit duplicate pairs.
 */
fun transactionMerkleRoot(transactions: List<Transaction>): ByteArray {
    if (transactions.isEmpty()) {
        throw BlockValidationError("block contains no transactions")
    }
    var level = transactions.map { transactionId(it) }
    while (level.size > 1) {
        var index = 0
        while (index + 1 < level.size) {
            if (equalBytes(level[index], level[index + 1])) {
                throw BlockValidationError("mutated merkle tree contains an explicit duplicate pair")
            }
            index += 2
        }
        if (level.size % 2 == 1) {
            level = level + listOf(level.last().copyOf())
        }
        val next = ArrayList<ByteArray>(level.size / 2)
        index = 0
        while (index < level.size) {
            val pair = ByteArray(64)
            level[index].copyInto(pair, 0)
            level[index + 1].copyInto(pair, 32)
            next.add(sha256d(pair))
            index += 2
        }
        level = next
    }
    return level[0]
}

/** Verify header hash (display order) and transaction merkle root. */
fun assertBlockPayload(payload: BlockPayload, expectedHashDisplay: String) {
    val actualHashDisplay = bytesToHex(sha256d(encodeBlockHeader(payload.header)).reversedArray())
    if (actualHashDisplay != expectedHashDisplay) {
        throw BlockValidationError(
            "block header hash $actualHashDisplay does not match requested $expectedHashDisplay",
        )
    }
    val actualMerkleRoot = transactionMerkleRoot(payload.transactions)
    if (!equalBytes(actualMerkleRoot, payload.header.merkleRoot)) {
        throw BlockValidationError(
            "block $expectedHashDisplay transaction merkle root mismatch",
        )
    }
}
