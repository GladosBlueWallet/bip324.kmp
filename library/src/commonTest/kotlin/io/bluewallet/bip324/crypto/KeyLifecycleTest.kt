package io.bluewallet.bip324.crypto

import io.bluewallet.bip324.FSChaCha20
import io.bluewallet.bip324.FSChaCha20Poly1305
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class KeyLifecycleTest {
    @Test
    fun destroyedForwardSecureCiphersRejectFurtherUse() {
        val stream = FSChaCha20(ByteArray(32) { 1 })
        val aead = FSChaCha20Poly1305(ByteArray(32) { 2 })
        stream.destroy()
        aead.destroy()
        assertFailsWith<IllegalStateException> { stream.encrypt(ByteArray(3)) }
        assertFailsWith<IllegalStateException> { aead.encrypt(ByteArray(0), ByteArray(1)) }
        assertFailsWith<IllegalStateException> { aead.decrypt(ByteArray(0), ByteArray(17)) }
    }

    @Test
    fun failedAeadAuthenticationStillAdvancesThePacketCounter() {
        val key = ByteArray(32) { 3 }
        val sender = FSChaCha20Poly1305(key)
        val receiver = FSChaCha20Poly1305(key)
        val first = sender.encrypt(ByteArray(0), byteArrayOf(1))
        val second = sender.encrypt(ByteArray(0), byteArrayOf(2))
        first[first.size - 1] = (first[first.size - 1].toInt() xor 1).toByte()
        assertNull(receiver.decrypt(ByteArray(0), first))
        assertContentEquals(byteArrayOf(2), receiver.decrypt(ByteArray(0), second))
    }
}
