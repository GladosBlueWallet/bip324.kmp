package io.bluewallet.bip324

private const val MAX_ADDR_COUNT = 1_000
private const val MAX_LOCATOR_HASHES = 101
private const val MAX_HEADERS = 2_000
private const val MAX_INVENTORY = 50_000
private const val MAX_ADDR_V2_LENGTH = 512
private const val MAX_FIELD_LENGTH = 0x00ff_ffff
private val BIP155_ADDRESS_LENGTHS = mapOf(
    1 to 4,
    2 to 16,
    3 to 10,
    4 to 32,
    5 to 32,
    6 to 16,
    7 to 16,
)
private const val MAX_EAGER_INPUTS = 25_000
private const val MAX_EAGER_OUTPUTS = 125_000
private const val MAX_EAGER_TRANSACTIONS = 100_000

class NetworkAddress(
    val services: ULong,
    val ip: ByteArray,
    val port: Int,
)

class VersionPayload(
    val version: Int,
    val services: ULong,
    val timestamp: Long,
    val receiver: NetworkAddress,
    val sender: NetworkAddress,
    val nonce: ULong,
    val userAgent: String,
    val startHeight: Int,
    val relay: Boolean? = true,
)

class TimedNetworkAddress(
    val time: UInt,
    val services: ULong,
    val ip: ByteArray,
    val port: Int,
)

class AddrPayload(
    val addresses: List<TimedNetworkAddress>,
)

class NetworkAddressV2(
    val time: UInt,
    val services: ULong,
    val networkId: Int,
    val address: ByteArray,
    val port: Int,
)

class AddrV2Payload(
    val addresses: List<NetworkAddressV2>,
)

class GetHeadersPayload(
    val version: Int,
    val locatorHashes: List<ByteArray>,
    val stopHash: ByteArray,
)

class BlockHeader(
    val version: Int,
    val previousBlockHash: ByteArray,
    val merkleRoot: ByteArray,
    val timestamp: UInt,
    val bits: UInt,
    val nonce: UInt,
)

class HeadersPayload(
    val headers: List<BlockHeader>,
)

class InventoryVector(
    val type: UInt,
    val hash: ByteArray,
)

class InventoryPayload(
    val inventory: List<InventoryVector>,
)

class OutPoint(
    val hash: ByteArray,
    val index: UInt,
)

/**
 * Lazily decoded witness items. This avoids allocating millions of tiny typed
 * arrays for compact but adversarial witness stacks.
 */
class WitnessStack(
    val length: Int,
    encodedItems: ByteArray,
) : Iterable<ByteArray> {
    private val encodedItems: ByteArray

    init {
        require(length >= 0) { "invalid witness length" }
        val reader = PayloadReader(encodedItems)
        repeat(length) { reader.skipVarBytes(MAX_FIELD_LENGTH) }
        reader.finish()
        this.encodedItems = encodedItems.copyOf()
    }

    override fun iterator(): Iterator<ByteArray> = iterator {
        val reader = PayloadReader(encodedItems)
        repeat(length) { yield(reader.varBytes(MAX_FIELD_LENGTH)) }
        reader.finish()
    }

    fun toArray(): List<ByteArray> = toList()

    fun writeTo(writer: PayloadWriter) {
        writer.compactSize(length).bytes(encodedItems)
    }
}

typealias Witness = List<ByteArray>

class TxInput(
    val previousOutput: OutPoint,
    val scriptSig: ByteArray,
    val sequence: UInt,
    var witness: Iterable<ByteArray>? = null,
)

class TxOutput(
    val value: Long,
    val scriptPubKey: ByteArray,
)

class Transaction(
    val version: UInt,
    val inputs: List<TxInput>,
    val outputs: List<TxOutput>,
    val lockTime: UInt,
)

class BlockPayload(
    val header: BlockHeader,
    val transactions: List<Transaction>,
)

fun encodeVersion(payload: VersionPayload): ByteArray {
    val writer = PayloadWriter()
    val userAgent = utf8ToBytes(payload.userAgent)
    if (userAgent.size > 256) throw IllegalArgumentException("version user agent exceeds 256 bytes")
    writer.i32le(payload.version).u64le(payload.services).i64le(payload.timestamp)
    writeNetworkAddress(writer, payload.receiver)
    writeNetworkAddress(writer, payload.sender)
    writer.u64le(payload.nonce).varBytes(userAgent).i32le(payload.startHeight)
    if (payload.relay != null) writer.u8(if (payload.relay) 1 else 0)
    return writer.finish()
}

fun decodeVersion(bytes: ByteArray): VersionPayload {
    val reader = PayloadReader(bytes)
    var relay: Boolean? = true
    val version = reader.i32le()
    val services = reader.u64le()
    val timestamp = reader.i64le()
    val receiver = readNetworkAddress(reader)
    val sender = readNetworkAddress(reader)
    val nonce = reader.u64le()
    val userAgent = reader.varString(256)
    val startHeight = reader.i32le()
    if (reader.remaining > 0) {
        val flag = reader.u8()
        if (flag > 1) throw IllegalArgumentException("version relay flag must be 0 or 1")
        relay = flag == 1
    }
    reader.finish()
    return VersionPayload(version, services, timestamp, receiver, sender, nonce, userAgent, startHeight, relay)
}

fun encodeAddr(payload: AddrPayload): ByteArray {
    if (payload.addresses.size > MAX_ADDR_COUNT) throw IllegalArgumentException("too many addr entries")
    val writer = PayloadWriter().compactSize(payload.addresses.size)
    for (address in payload.addresses) {
        writer.u32le(address.time)
        writeNetworkAddress(writer, NetworkAddress(address.services, address.ip, address.port))
    }
    return writer.finish()
}

fun decodeAddr(bytes: ByteArray): AddrPayload {
    val reader = PayloadReader(bytes)
    val count = reader.compactSize(MAX_ADDR_COUNT)
    val addresses = ArrayList<TimedNetworkAddress>(count)
    repeat(count) {
        val time = reader.u32le()
        val net = readNetworkAddress(reader)
        addresses.add(TimedNetworkAddress(time, net.services, net.ip, net.port))
    }
    reader.finish()
    return AddrPayload(addresses)
}

fun encodeAddrV2(payload: AddrV2Payload): ByteArray {
    if (payload.addresses.size > MAX_ADDR_COUNT) throw IllegalArgumentException("too many addrv2 entries")
    val writer = PayloadWriter().compactSize(payload.addresses.size)
    for (address in payload.addresses) {
        validateAddrV2(address.networkId, address.address.size)
        writer
            .u32le(address.time)
            .compactSize(address.services)
            .u8(address.networkId)
            .varBytes(address.address)
            .u16be(address.port)
    }
    return writer.finish()
}

fun decodeAddrV2(bytes: ByteArray): AddrV2Payload {
    val reader = PayloadReader(bytes)
    val count = reader.compactSize(MAX_ADDR_COUNT)
    val addresses = ArrayList<NetworkAddressV2>(count)
    repeat(count) {
        val time = reader.u32le()
        val services = reader.compactSizeULong()
        val networkId = reader.u8()
        val address = reader.varBytes(MAX_ADDR_V2_LENGTH)
        validateAddrV2(networkId, address.size)
        addresses.add(NetworkAddressV2(time, services, networkId, address, reader.u16be()))
    }
    reader.finish()
    return AddrV2Payload(addresses)
}

fun encodeGetHeaders(payload: GetHeadersPayload): ByteArray {
    if (payload.locatorHashes.size > MAX_LOCATOR_HASHES) {
        throw IllegalArgumentException("too many block locator hashes")
    }
    assertLength(payload.stopHash, 32, "stop hash")
    val writer = PayloadWriter()
        .i32le(payload.version)
        .compactSize(payload.locatorHashes.size)
    for (hash in payload.locatorHashes) {
        assertLength(hash, 32, "locator hash")
        writer.bytes(hash)
    }
    return writer.bytes(payload.stopHash).finish()
}

fun decodeGetHeaders(bytes: ByteArray): GetHeadersPayload {
    val reader = PayloadReader(bytes)
    val version = reader.i32le()
    val count = reader.compactSize(MAX_LOCATOR_HASHES)
    val locatorHashes = ArrayList<ByteArray>(count)
    repeat(count) { locatorHashes.add(reader.bytes(32)) }
    val stopHash = reader.bytes(32)
    reader.finish()
    return GetHeadersPayload(version, locatorHashes, stopHash)
}

fun encodeHeaders(payload: HeadersPayload): ByteArray {
    if (payload.headers.size > MAX_HEADERS) throw IllegalArgumentException("too many headers")
    val writer = PayloadWriter().compactSize(payload.headers.size)
    for (header in payload.headers) {
        writer.bytes(encodeBlockHeader(header)).compactSize(0)
    }
    return writer.finish()
}

fun decodeHeaders(bytes: ByteArray): HeadersPayload {
    val reader = PayloadReader(bytes)
    val count = reader.compactSize(MAX_HEADERS)
    val headers = ArrayList<BlockHeader>(count)
    repeat(count) {
        headers.add(readBlockHeader(reader))
        if (reader.compactSizeULong() != 0uL) {
            throw IllegalArgumentException("headers transaction count must be zero")
        }
    }
    reader.finish()
    return HeadersPayload(headers)
}

fun encodeInventory(payload: InventoryPayload): ByteArray {
    if (payload.inventory.size > MAX_INVENTORY) throw IllegalArgumentException("too many inventory entries")
    val writer = PayloadWriter().compactSize(payload.inventory.size)
    for (item in payload.inventory) {
        assertLength(item.hash, 32, "inventory hash")
        writer.u32le(item.type).bytes(item.hash)
    }
    return writer.finish()
}

fun decodeInventory(bytes: ByteArray): InventoryPayload {
    val reader = PayloadReader(bytes)
    val count = reader.compactSize(MAX_INVENTORY)
    val inventory = ArrayList<InventoryVector>(count)
    repeat(count) {
        inventory.add(InventoryVector(reader.u32le(), reader.bytes(32)))
    }
    reader.finish()
    return InventoryPayload(inventory)
}

fun encodeTransaction(transaction: Transaction): ByteArray {
    val writer = PayloadWriter()
    writeTransaction(writer, transaction)
    return writer.finish()
}

fun decodeTransaction(bytes: ByteArray): Transaction {
    val reader = PayloadReader(bytes)
    val transaction = readTransaction(reader, AllocationBudget())
    reader.finish()
    return transaction
}

fun encodeBlock(payload: BlockPayload): ByteArray {
    val writer = PayloadWriter()
        .bytes(encodeBlockHeader(payload.header))
        .compactSize(payload.transactions.size)
    for (transaction in payload.transactions) writer.bytes(encodeTransaction(transaction))
    return writer.finish()
}

fun decodeBlock(bytes: ByteArray): BlockPayload {
    val reader = PayloadReader(bytes)
    val budget = AllocationBudget()
    val header = readBlockHeader(reader)
    val count = byteBoundedCount(reader, 10, "transactions")
    budget.take("transactions", count)
    val transactions = ArrayList<Transaction>(count)
    repeat(count) { transactions.add(readTransaction(reader, budget)) }
    reader.finish()
    return BlockPayload(header, transactions)
}

fun encodeBlockHeader(header: BlockHeader): ByteArray {
    assertLength(header.previousBlockHash, 32, "previous block hash")
    assertLength(header.merkleRoot, 32, "merkle root")
    return PayloadWriter()
        .i32le(header.version)
        .bytes(header.previousBlockHash)
        .bytes(header.merkleRoot)
        .u32le(header.timestamp)
        .u32le(header.bits)
        .u32le(header.nonce)
        .finish()
}

private fun readBlockHeader(reader: PayloadReader): BlockHeader =
    BlockHeader(
        version = reader.i32le(),
        previousBlockHash = reader.bytes(32),
        merkleRoot = reader.bytes(32),
        timestamp = reader.u32le(),
        bits = reader.u32le(),
        nonce = reader.u32le(),
    )

private class EncodedWitness(val stack: WitnessStack?, val items: List<ByteArray>?)

private fun writeTransaction(writer: PayloadWriter, transaction: Transaction) {
    val witnesses = transaction.inputs.map { input ->
        when (val w = input.witness) {
            null -> EncodedWitness(null, null)
            is WitnessStack -> EncodedWitness(w, null)
            else -> EncodedWitness(null, w.toList())
        }
    }
    val hasWitness = witnesses.any { w ->
        (w.stack != null && w.stack.length > 0) || !w.items.isNullOrEmpty()
    }
    writer.u32le(transaction.version)
    if (hasWitness) writer.u8(0).u8(1)
    writer.compactSize(transaction.inputs.size)
    for (input in transaction.inputs) {
        assertLength(input.previousOutput.hash, 32, "outpoint hash")
        if (input.scriptSig.size > MAX_FIELD_LENGTH) throw IllegalArgumentException("scriptSig too long")
        writer
            .bytes(input.previousOutput.hash)
            .u32le(input.previousOutput.index)
            .varBytes(input.scriptSig)
            .u32le(input.sequence)
    }
    writer.compactSize(transaction.outputs.size)
    for (output in transaction.outputs) {
        if (output.scriptPubKey.size > MAX_FIELD_LENGTH) throw IllegalArgumentException("scriptPubKey too long")
        writer.i64le(output.value).varBytes(output.scriptPubKey)
    }
    if (hasWitness) {
        for (witness in witnesses) {
            val stack = witness.stack
            val items = witness.items
            when {
                stack != null -> stack.writeTo(writer)
                items != null -> {
                    writer.compactSize(items.size)
                    for (item in items) {
                        if (item.size > MAX_FIELD_LENGTH) throw IllegalArgumentException("witness item too long")
                        writer.varBytes(item)
                    }
                }
                else -> writer.compactSize(0)
            }
        }
    }
    writer.u32le(transaction.lockTime)
}

private fun readTransaction(reader: PayloadReader, budget: AllocationBudget): Transaction {
    val version = reader.u32le()
    var flags = 0
    var inputCount = reader.compactSize()
    budget.take("inputs", inputCount)
    if (inputCount == 0) {
        flags = reader.u8()
        if (flags == 0) throw IllegalArgumentException("transaction witness flags must not be zero")
        inputCount = byteBoundedCount(reader, 41, "transaction inputs")
        budget.take("inputs", inputCount)
    } else if (inputCount > reader.remaining / 41) {
        throw IllegalArgumentException("transaction inputs exceed remaining payload")
    }
    val inputs = ArrayList<TxInput>(inputCount)
    repeat(inputCount) {
        inputs.add(
            TxInput(
                previousOutput = OutPoint(reader.bytes(32), reader.u32le()),
                scriptSig = reader.varBytes(MAX_FIELD_LENGTH),
                sequence = reader.u32le(),
            ),
        )
    }
    val outputCount = byteBoundedCount(reader, 9, "transaction outputs")
    budget.take("outputs", outputCount)
    val outputs = ArrayList<TxOutput>(outputCount)
    repeat(outputCount) {
        outputs.add(TxOutput(reader.i64le(), reader.varBytes(MAX_FIELD_LENGTH)))
    }
    if ((flags and 1) != 0) {
        var hasWitness = false
        for (input in inputs) {
            val count = byteBoundedCount(reader, 1, "witness items")
            val start = reader.position
            repeat(count) { reader.skipVarBytes(MAX_FIELD_LENGTH) }
            if (count > 0) hasWitness = true
            input.witness = WitnessStack(count, reader.data.copyOfRange(start, reader.position))
        }
        if (!hasWitness) throw IllegalArgumentException("superfluous transaction witness record")
        flags = flags xor 1
    }
    if (flags != 0) throw IllegalArgumentException("unsupported transaction witness flags: $flags")
    return Transaction(version, inputs, outputs, reader.u32le())
}

private fun writeNetworkAddress(writer: PayloadWriter, address: NetworkAddress) {
    assertLength(address.ip, 16, "network address IP")
    writer.u64le(address.services).bytes(address.ip).u16be(address.port)
}

private fun readNetworkAddress(reader: PayloadReader): NetworkAddress =
    NetworkAddress(reader.u64le(), reader.bytes(16), reader.u16be())

private fun validateAddrV2(networkId: Int, length: Int) {
    if (networkId !in 0..255) throw IllegalArgumentException("invalid addrv2 network ID: $networkId")
    if (length > MAX_ADDR_V2_LENGTH) throw IllegalArgumentException("addrv2 address length exceeds 512")
    val expected = BIP155_ADDRESS_LENGTHS[networkId]
    if (expected != null && length != expected) {
        throw IllegalArgumentException("addrv2 network $networkId address length must be $expected, got $length")
    }
}

private fun assertLength(bytes: ByteArray, expected: Int, name: String) {
    if (bytes.size != expected) throw IllegalArgumentException("$name must be $expected bytes")
}

private fun byteBoundedCount(reader: PayloadReader, minimumItemBytes: Int, label: String): Int {
    val count = reader.compactSize()
    if (count > reader.remaining / minimumItemBytes) {
        throw IllegalArgumentException("$label exceed remaining payload")
    }
    return count
}

private class AllocationBudget {
    private var inputs = MAX_EAGER_INPUTS
    private var outputs = MAX_EAGER_OUTPUTS
    private var transactions = MAX_EAGER_TRANSACTIONS

    fun take(kind: String, count: Int) {
        when (kind) {
            "inputs" -> {
                if (count > inputs) throw IllegalArgumentException("inputs exceed aggregate allocation limit")
                inputs -= count
            }
            "outputs" -> {
                if (count > outputs) throw IllegalArgumentException("outputs exceed aggregate allocation limit")
                outputs -= count
            }
            "transactions" -> {
                if (count > transactions) {
                    throw IllegalArgumentException("transactions exceed aggregate allocation limit")
                }
                transactions -= count
            }
        }
    }
}
