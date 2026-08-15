package org.bitcoin.bip324

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.concurrent.Volatile

class ProtocolOptions(
    val role: Role,
    val network: Network,
    val garbage: ByteArray = ByteArray(0),
    val createKeyPair: (() -> EllswiftKeyPair)? = null,
)

/**
 * Thin session helper: BIP-324 handshake + encrypted message I/O over an injected duplex.
 */
class Protocol private constructor(
    private val duplex: ByteDuplex,
    private val session: CipherSession,
    val role: Role,
) {
    private val sendMutex = Mutex()
    private val recvMutex = Mutex()
    private val closeMutex = Mutex()
    @Volatile private var closed = false
    private var inFlight = 0
    private var sessionDestroyed = false
    private var closeDone: CompletableDeferred<Unit>? = null

    val sessionId: ByteArray
        get() = session.sessionId.copyOf()

    val isClosed: Boolean
        get() = closed

    companion object {
        suspend fun connect(duplex: ByteDuplex, opts: ProtocolOptions): Protocol {
            try {
                val result = performHandshake(
                    duplex,
                    HandshakeOptions(
                        role = opts.role,
                        network = opts.network,
                        garbage = opts.garbage,
                        createKeyPair = opts.createKeyPair ?: { ellswiftCreate() },
                    ),
                )
                if (result is V1HandshakeResult) throw V1DetectedError(result.buffered)
                val v2 = result as V2HandshakeResult
                return Protocol(duplex, v2.session, v2.role)
            } catch (error: Throwable) {
                if (error is V1DetectedError) throw error
                withContext(NonCancellable) {
                    try {
                        duplex.close()
                    } catch (_: Throwable) {
                        // Preserve the protocol/transport error that caused teardown.
                    }
                }
                throw error
            }
        }
    }

    suspend fun writeMessage(msg: Message) {
        val contents = encodeMessage(msg)
        sendMutex.withLock {
            closeMutex.withLock {
                assertOpen()
                inFlight += 1
            }
            try {
                if (contents.size > MAX_CONTENTS_LEN) {
                    throw IllegalArgumentException("contents too large: ${contents.size}")
                }
                val packet = encodePacket(session, contents)
                try {
                    duplex.write(packet)
                } catch (error: Throwable) {
                    invalidate()
                    throw error
                }
            } finally {
                finishOp()
            }
        }
    }

    suspend fun readMessage(): Message {
        return recvMutex.withLock {
            closeMutex.withLock {
                assertOpen()
                inFlight += 1
            }
            try {
                val contents = decodePacket(session, duplex, DecodePacketOpts(destroyOnError = false))
                decodeMessage(contents)
            } catch (error: Throwable) {
                invalidate()
                throw error
            } finally {
                finishOp()
            }
        }
    }

    suspend fun close() {
        val (done, shouldCloseDuplex) = beginClose()
        if (shouldCloseDuplex) {
            try {
                withContext(NonCancellable) { duplex.close() }
                done.complete(Unit)
            } catch (error: Throwable) {
                done.completeExceptionally(error)
                throw error
            }
        }
        done.await()
    }

    private fun assertOpen() {
        if (closed) throw ProtocolClosedError()
    }

    private suspend fun invalidate() {
        val (done, shouldCloseDuplex) = beginClose()
        if (shouldCloseDuplex) {
            try {
                withContext(NonCancellable) { duplex.close() }
                done.complete(Unit)
            } catch (_: Throwable) {
                done.complete(Unit)
            }
        } else {
            try {
                done.await()
            } catch (_: Throwable) {
                // The triggering error is more useful than a secondary close failure.
            }
        }
    }

    private suspend fun beginClose(): Pair<CompletableDeferred<Unit>, Boolean> =
        closeMutex.withLock {
            val existing = closeDone
            if (existing != null) {
                existing to false
            } else {
                closed = true
                destroyIfIdleLocked()
                val done = CompletableDeferred<Unit>()
                closeDone = done
                done to true
            }
        }

    private suspend fun finishOp() {
        closeMutex.withLock {
            inFlight -= 1
            if (closed) destroyIfIdleLocked()
        }
    }

    private fun destroyIfIdleLocked() {
        if (!sessionDestroyed && inFlight == 0) {
            destroySession(session)
            sessionDestroyed = true
        }
    }
}
