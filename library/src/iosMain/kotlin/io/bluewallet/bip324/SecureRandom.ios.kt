package io.bluewallet.bip324

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecSuccess
import platform.Security.kSecRandomDefault
import platform.Foundation.NSDate
import platform.Foundation.timeIntervalSince1970

@OptIn(ExperimentalForeignApi::class)
internal actual fun fillSecureRandom(bytes: ByteArray) {
    if (bytes.isEmpty()) return
    val status = bytes.usePinned { pinned ->
        SecRandomCopyBytes(kSecRandomDefault, bytes.size.convert(), pinned.addressOf(0))
    }
    check(status == errSecSuccess) { "SecRandomCopyBytes failed: $status" }
}

internal actual fun currentEpochSeconds(): Long =
    NSDate().timeIntervalSince1970.toLong()
