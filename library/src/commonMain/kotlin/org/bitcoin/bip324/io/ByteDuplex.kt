package org.bitcoin.bip324

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private class DuplexSide {
    val inbox = ArrayDeque<ByteArray>()
    var closed = false
    var peerClosed = false
    var waiter: Waiter? = null
    val mutex = Mutex()
}

private class Waiter(
    val n: Int,
    val deferred: CompletableDeferred<ByteArray>,
)

/** In-memory paired duplexes for tests (left ↔ right). */
fun pairedByteDuplexes(): Pair<ByteDuplex, ByteDuplex> {
    val leftState = DuplexSide()
    val rightState = DuplexSide()

    fun take(state: DuplexSide, n: Int): ByteArray? {
        val chunk = state.inbox.firstOrNull() ?: return null
        return if (chunk.size <= n) {
            state.inbox.removeFirst()
            chunk
        } else {
            val result = chunk.copyOf(n)
            state.inbox[0] = chunk.copyOfRange(n, chunk.size)
            result
        }
    }

    fun wake(state: DuplexSide) {
        val waiter = state.waiter ?: return
        if (state.closed) {
            state.waiter = null
            waiter.deferred.complete(ByteArray(0))
            return
        }
        val chunk = take(state, waiter.n)
        if (chunk != null) {
            state.waiter = null
            waiter.deferred.complete(chunk)
        } else if (state.peerClosed) {
            state.waiter = null
            waiter.deferred.complete(ByteArray(0))
        }
    }

    fun make(state: DuplexSide, peer: DuplexSide): ByteDuplex =
        object : ByteDuplex {
            override suspend fun read(n: Int): ByteArray {
                val deferred: CompletableDeferred<ByteArray>? = state.mutex.withLock {
                    if (state.closed) return ByteArray(0)
                    val chunk = take(state, n)
                    if (chunk != null) return chunk
                    if (state.peerClosed) return ByteArray(0)
                    check(state.waiter == null) { "concurrent reads are not supported" }
                    val waiter = Waiter(n, CompletableDeferred())
                    state.waiter = waiter
                    waiter.deferred
                }
                return deferred?.await() ?: ByteArray(0)
            }

            override suspend fun write(bytes: ByteArray) {
                peer.mutex.withLock {
                    if (state.closed || peer.closed) {
                        throw IllegalStateException("cannot write to closed duplex")
                    }
                    peer.inbox.addLast(bytes.copyOf())
                    wake(peer)
                }
            }

            override suspend fun close() {
                state.mutex.withLock {
                    if (state.closed) return
                    state.closed = true
                    wake(state)
                }
                peer.mutex.withLock {
                    peer.peerClosed = true
                    wake(peer)
                }
            }
        }

    return make(leftState, rightState) to make(rightState, leftState)
}
