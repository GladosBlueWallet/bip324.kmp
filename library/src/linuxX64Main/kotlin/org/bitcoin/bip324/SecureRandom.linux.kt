package org.bitcoin.bip324

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.posix.O_RDONLY
import platform.posix.close
import platform.posix.open
import platform.posix.read
import platform.posix.time

@OptIn(ExperimentalForeignApi::class)
internal actual fun fillSecureRandom(bytes: ByteArray) {
    if (bytes.isEmpty()) return
    val fd = open("/dev/urandom", O_RDONLY)
    check(fd >= 0) { "cannot open /dev/urandom" }
    try {
        bytes.usePinned { pinned ->
            var off = 0
            while (off < bytes.size) {
                val n = read(fd, pinned.addressOf(off), (bytes.size - off).convert())
                check(n > 0) { "short read from /dev/urandom" }
                off += n.toInt()
            }
        }
    } finally {
        close(fd)
    }
}

internal actual fun currentEpochSeconds(): Long = time(null)
