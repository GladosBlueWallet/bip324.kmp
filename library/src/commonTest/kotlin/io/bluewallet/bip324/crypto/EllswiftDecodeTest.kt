package io.bluewallet.bip324.crypto

import io.bluewallet.bip324.bytesToHex
import io.bluewallet.bip324.ellswiftDecode
import io.bluewallet.bip324.helpers.Bip324VectorData
import io.bluewallet.bip324.helpers.parseCsv
import io.bluewallet.bip324.hexToBytes
import kotlin.test.Test
import kotlin.test.assertEquals

class EllswiftDecodeTest {
    @Test
    fun ellswiftDecodeBipVectors() {
        val rows = parseCsv(Bip324VectorData.ellswift_decode_test_vectors)
        for (row in rows) {
            val got = ellswiftDecode(hexToBytes(row.getValue("ellswift")))
            assertEquals(row.getValue("x"), bytesToHex(got))
        }
    }
}
