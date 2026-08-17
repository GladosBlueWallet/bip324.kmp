package io.bluewallet.bip324

enum class NetworkName {
    Mainnet,
    Testnet3,
    Signet,
    Regtest,
}

class Network internal constructor(
    val name: NetworkName,
    private val magicBytes: ByteArray,
    val defaultPort: Int,
) {
    /** 4-byte network magic used in BIP-324 HKDF salt and v1 detection. */
    val magic: ByteArray
        get() = magicBytes.copyOf()
}

object Networks {
    val mainnet: Network = Network(NetworkName.Mainnet, byteArrayOf(0xf9.toByte(), 0xbe.toByte(), 0xb4.toByte(), 0xd9.toByte()), 8333)
    val testnet3: Network = Network(NetworkName.Testnet3, byteArrayOf(0x0b, 0x11, 0x09, 0x07), 18_333)
    val signet: Network = Network(NetworkName.Signet, byteArrayOf(0x0a, 0x03, 0xcf.toByte(), 0x40), 38_333)
    val regtest: Network = Network(NetworkName.Regtest, byteArrayOf(0xfa.toByte(), 0xbf.toByte(), 0xb5.toByte(), 0xda.toByte()), 18_444)
}
