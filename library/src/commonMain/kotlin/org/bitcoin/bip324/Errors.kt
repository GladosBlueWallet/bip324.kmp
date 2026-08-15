package org.bitcoin.bip324

open class Bip324Error(
    message: String,
    val code: String,
    cause: Throwable? = null,
) : Exception(message, cause)

class AuthenticationError(
    message: String = "BIP-324 packet authentication failed",
) : Bip324Error(message, "ERR_BIP324_AUTHENTICATION")

class ProtocolClosedError(
    cause: Throwable? = null,
) : Bip324Error("BIP-324 protocol session is closed", "ERR_BIP324_CLOSED", cause)

class V1DetectedError(
    buffered: ByteArray,
) : Bip324Error("peer selected Bitcoin P2P v1 transport", "ERR_BIP324_V1_DETECTED") {
    val buffered: ByteArray = buffered.copyOf()
}

class BlockValidationError(message: String) : Exception(message)
