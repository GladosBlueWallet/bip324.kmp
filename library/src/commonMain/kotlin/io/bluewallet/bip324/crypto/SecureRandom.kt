package io.bluewallet.bip324

internal expect fun fillSecureRandom(bytes: ByteArray)

internal expect fun currentEpochSeconds(): Long
