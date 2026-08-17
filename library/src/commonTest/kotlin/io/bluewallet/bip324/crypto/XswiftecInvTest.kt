package io.bluewallet.bip324.crypto

import io.bluewallet.bip324.bytesToHex
import io.bluewallet.bip324.helpers.Bip324VectorData
import io.bluewallet.bip324.helpers.parseCsv
import io.bluewallet.bip324.hexToBytes
import io.bluewallet.bip324.xswiftecInv
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class XswiftecInvTest {
    @Test
    fun xswiftecInverseBipVectors() {
        val rows = parseCsv(Bip324VectorData.xswiftec_inv_test_vectors)
        for ((rowIndex, row) in rows.withIndex()) {
            for (ellCase in 0 until 8) {
                val expected = row["case${ellCase}_t"].orEmpty()
                val actual = xswiftecInv(
                    hexToBytes(row.getValue("x")),
                    hexToBytes(row.getValue("u")),
                    ellCase,
                )
                if (expected.isNotEmpty()) {
                    assertEquals(expected, bytesToHex(actual!!), "row=$rowIndex case=$ellCase")
                } else {
                    assertNull(actual, "row=$rowIndex case=$ellCase")
                }
            }
        }
    }
}
