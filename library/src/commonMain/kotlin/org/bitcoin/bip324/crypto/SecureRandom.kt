package org.bitcoin.bip324

internal expect fun fillSecureRandom(bytes: ByteArray)

internal expect fun currentEpochSeconds(): Long
