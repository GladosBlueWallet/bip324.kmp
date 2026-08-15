package org.bitcoin.bip324.crypto

import org.bitcoin.bip324.Ge
import org.bitcoin.bip324.bytesToHex
import org.bitcoin.bip324.ellswiftCreate
import org.bitcoin.bip324.ellswiftDecode
import org.bitcoin.bip324.ellswiftEcdhXonly
import org.bitcoin.bip324.hexToBytes
import org.bitcoin.bip324.v2Ecdh
import org.bitcoin.bip324.xswiftecInv
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Secp256k1Test {
    @Test
    fun generatorDoublingAndEcdhRoundtrip() {
        val two = hexToBytes("0000000000000000000000000000000000000000000000000000000000000002")
        val g2 = assertNotNull(Ge.G * two)
        assertEquals(
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            bytesToHex(g2.x.toBytes()),
        )
        assertEquals(
            "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
            bytesToHex(g2.y.toBytes()),
        )

        val a = ellswiftCreate()
        val b = ellswiftCreate()
        val xa = ellswiftDecode(a.publicKey)
        val xb = ellswiftDecode(b.publicKey)
        assertEquals(32, xa.size)
        assertEquals(32, xb.size)
        val secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true)
        val secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false)
        assertEquals(bytesToHex(secretA), bytesToHex(secretB))
        assertEquals(
            bytesToHex(ellswiftEcdhXonly(b.publicKey, a.privateKey)),
            bytesToHex(ellswiftEcdhXonly(a.publicKey, b.privateKey)),
        )
        assertTrue(secretA.any { it != 0.toByte() })
    }

    @Test
    fun ellswiftEncodingCaseIsIndependentOfU() {
        var correlated = 0
        repeat(16) {
            val kp = ellswiftCreate()
            val u = kp.publicKey.copyOfRange(0, 32)
            val t = kp.publicKey.copyOfRange(32, 64)
            val x = ellswiftDecode(kp.publicKey)
            val uMod8 = u[31].toInt() and 7
            var recovered = -1
            for (c in 0..7) {
                val inv = xswiftecInv(x, u, c) ?: continue
                if (inv.contentEquals(t)) {
                    recovered = c
                    break
                }
            }
            assertTrue(recovered in 0..7)
            if (recovered == uMod8) correlated += 1
        }
        assertTrue(correlated < 16, "ellswift case leaked u mod 8 in all $correlated encodings")
    }
}
