package io.bluewallet.bip324.crypto

import io.bluewallet.bip324.hexToBytes
import kotlin.test.Test
import kotlin.test.assertFailsWith

class BytesTest {
    @Test
    fun hexToBytesRejectsNonHexInputInsteadOfSilentlyProducingZeros() {
        assertFailsWith<IllegalArgumentException> { hexToBytes("0g") }
        assertFailsWith<IllegalArgumentException> { hexToBytes("zz") }
    }
}
