@file:OptIn(ExperimentalUnsignedTypes::class)

package io.bluewallet.bip324

/**
 * secp256k1 field element GF(p), p = 2^256 - 2^32 - 977.
 * 8×32-bit little-endian limbs; matches BIP-324 `reference.py` `FE`.
 */
internal class Fe private constructor(private val d: IntArray) {
    companion object {
        val ZERO = Fe(IntArray(8))
        val ONE = Fe(intArrayOf(1, 0, 0, 0, 0, 0, 0, 0))

        private val P_LIMBS = intArrayOf(
            0xFFFFFC2F.toInt(),
            0xFFFFFFFE.toInt(),
            -1, -1, -1, -1, -1, -1,
        )

        /** p - 2, for Fermat inversion. */
        private val INV_EXP = hexToBytes("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d")

        /** (p + 1) / 4, for square roots since p ≡ 3 (mod 4). */
        private val SQRT_EXP = hexToBytes("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c")

        /** (p - 1) / 2, Euler's criterion. */
        private val LEGENDRE_EXP = hexToBytes("7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17")

        val HALF: Fe by lazy { invoke(2).inv() }

        operator fun invoke(value: Int): Fe {
            if (value == 0) return ZERO
            if (value == 1) return ONE
            if (value > 0) {
                val d = IntArray(8)
                d[0] = value
                return Fe(d)
            }
            return invoke(-value).unaryMinus()
        }

        fun fromBytes(bytes: ByteArray): Fe? {
            require(bytes.size == 32) { "field element must be 32 bytes" }
            val d = parseBe(bytes)
            return if (gteP(d)) null else Fe(d)
        }

        fun fromBytesMod(bytes: ByteArray): Fe {
            require(bytes.size == 32) { "field element must be 32 bytes" }
            val d = parseBe(bytes)
            return if (gteP(d)) Fe(subP(d)) else Fe(d)
        }

        private fun parseBe(bytes: ByteArray): IntArray {
            val d = IntArray(8)
            for (i in 0..7) {
                val o = (7 - i) * 4
                d[i] = (bytes.u8(o) shl 24) or (bytes.u8(o + 1) shl 16) or
                    (bytes.u8(o + 2) shl 8) or bytes.u8(o + 3)
            }
            return d
        }

        private fun gteP(d: IntArray): Boolean {
            for (i in 7 downTo 0) {
                val a = d[i].toUInt()
                val b = P_LIMBS[i].toUInt()
                if (a != b) return a > b
            }
            return true
        }

        private fun subP(d: IntArray): IntArray = subLimbs(d, P_LIMBS)

        private fun subLimbs(a: IntArray, b: IntArray): IntArray {
            val out = IntArray(8)
            var borrow = 0L
            for (i in 0..7) {
                var v = u32(a[i]) - u32(b[i]) - borrow
                if (v < 0) {
                    v += 0x1_0000_0000L
                    borrow = 1
                } else {
                    borrow = 0
                }
                out[i] = v.toInt()
            }
            return out
        }

        private fun addP(d: IntArray): IntArray {
            val out = IntArray(8)
            var carry = 0L
            for (i in 0..7) {
                val v = u32(d[i]) + u32(P_LIMBS[i]) + carry
                out[i] = v.toInt()
                carry = v ushr 32
            }
            return out
        }

        private fun u32(v: Int): Long = v.toLong() and 0xffffffffL

        private fun limb(v: Int): ULong = v.toULong() and 0xffffffffuL

        private fun add64(acc: ULongArray, index: Int, value: ULong) {
            val lo = value and 0xffffffffuL
            val hi = value shr 32
            var s = acc[index] + lo
            acc[index] = s and 0xffffffffuL
            s = acc[index + 1] + hi + (s shr 32)
            acc[index + 1] = s and 0xffffffffuL
            var i = index + 2
            var c = s shr 32
            while (c != 0uL) {
                s = acc[i] + c
                acc[i] = s and 0xffffffffuL
                c = s shr 32
                i++
            }
        }

        private fun reduce256(d: IntArray, carry: ULong): Fe {
            var limbs = d
            if (carry != 0uL) {
                limbs = limbs.copyOf()
                var k = 0x1000003D1uL + limb(limbs[0])
                limbs[0] = (k and 0xffffffffuL).toInt()
                k = (k shr 32) + limb(limbs[1])
                limbs[1] = (k and 0xffffffffuL).toInt()
                k = k shr 32
                var i = 2
                while (k != 0uL && i < 8) {
                    k += limb(limbs[i])
                    limbs[i] = (k and 0xffffffffuL).toInt()
                    k = k shr 32
                    i++
                }
            }
            return if (gteP(limbs)) Fe(subP(limbs)) else Fe(limbs)
        }

        private fun reduceWide(w: ULongArray): Fe {
            fun fold() {
                var any = false
                val hi = ULongArray(8)
                for (i in 0 until 8) {
                    val v = w[8 + i]
                    if (v != 0uL) {
                        hi[i] = v
                        w[8 + i] = 0uL
                        any = true
                    }
                }
                if (!any) return
                for (i in 0 until 8) {
                    val v = hi[i]
                    if (v == 0uL) continue
                    add64(w, i, v * 977uL)
                    add64(w, i + 1, v)
                }
            }
            fold()
            fold()
            if (w[8] != 0uL) {
                val v = w[8]
                w[8] = 0uL
                add64(w, 0, v * 977uL)
                add64(w, 1, v)
            }
            val d = IntArray(8) { w[it].toInt() }
            return if (gteP(d)) Fe(subP(d)) else Fe(d)
        }
    }

    fun isZero(): Boolean {
        var x = 0
        for (limb in d) x = x or limb
        return x == 0
    }

    fun sqr(): Fe = this * this

    fun times2(): Fe = this + this

    operator fun plus(other: Fe): Fe {
        val out = IntArray(8)
        var carry = 0uL
        for (i in 0..7) {
            val s = limb(d[i]) + limb(other.d[i]) + carry
            out[i] = (s and 0xffffffffuL).toInt()
            carry = s shr 32
        }
        return reduce256(out, carry)
    }

    operator fun plus(other: Int): Fe = this + invoke(other)

    operator fun minus(other: Fe): Fe {
        val out = IntArray(8)
        var borrow = 0L
        for (i in 0..7) {
            var v = u32(d[i]) - u32(other.d[i]) - borrow
            if (v < 0) {
                v += 0x1_0000_0000L
                borrow = 1
            } else {
                borrow = 0
            }
            out[i] = v.toInt()
        }
        return if (borrow != 0L) Fe(addP(out)) else Fe(out)
    }

    operator fun minus(other: Int): Fe = this - invoke(other)

    operator fun unaryMinus(): Fe {
        if (isZero()) return this
        return Fe(subLimbs(P_LIMBS, d))
    }

    operator fun times(other: Fe): Fe {
        val acc = ULongArray(18)
        for (i in 0..7) {
            val ai = limb(d[i])
            if (ai == 0uL) continue
            for (j in 0..7) {
                val bj = limb(other.d[j])
                if (bj == 0uL) continue
                add64(acc, i + j, ai * bj)
            }
        }
        return reduceWide(acc)
    }

    operator fun times(other: Int): Fe {
        if (other == 0) return ZERO
        if (other == 1) return this
        if (other == 2) return times2()
        if (other == 3) return this + times2()
        if (other == 4) {
            val t = times2()
            return t + t
        }
        if (other == 8) {
            val t = times2()
            val q = t + t
            return q + q
        }
        if (other < 0) return -(this * -other)
        return this * invoke(other)
    }

    operator fun div(other: Fe): Fe = this * other.inv()

    operator fun div(other: Int): Fe = if (other == 2) this * HALF else this / invoke(other)

    fun pow(exp: Int): Fe {
        require(exp >= 0)
        return when (exp) {
            0 -> ONE
            1 -> this
            2 -> sqr()
            3 -> sqr() * this
            else -> {
                var result = ONE
                var base = this
                var e = exp
                while (e > 0) {
                    if (e and 1 != 0) result = result * base
                    base = base.sqr()
                    e = e shr 1
                }
                result
            }
        }
    }

    private fun pow(exp: ByteArray): Fe {
        var result = ONE
        var started = false
        for (byte in exp) {
            val ub = byte.toInt() and 0xff
            for (s in 7 downTo 0) {
                if (started) result = result.sqr()
                if (((ub shr s) and 1) != 0) {
                    result = if (!started) this else result * this
                    started = true
                }
            }
        }
        return if (started) result else ONE
    }

    fun inv(): Fe {
        check(!isZero()) { "inversion of zero" }
        return pow(INV_EXP)
    }

    fun sqrt(): Fe? {
        if (isZero()) return ZERO
        val s = pow(SQRT_EXP)
        return if (s.sqr() == this) s else null
    }

    fun isSquare(): Boolean {
        if (isZero()) return true
        return pow(LEGENDRE_EXP) == ONE
    }

    fun toBytes(): ByteArray {
        val out = ByteArray(32)
        for (i in 0..7) {
            val v = d[7 - i]
            val o = i * 4
            out[o] = (v ushr 24).toByte()
            out[o + 1] = (v ushr 16).toByte()
            out[o + 2] = (v ushr 8).toByte()
            out[o + 3] = v.toByte()
        }
        return out
    }

    override fun equals(other: Any?): Boolean {
        if (other !is Fe) return false
        var x = 0
        for (i in 0..7) x = x or (d[i] xor other.d[i])
        return x == 0
    }

    override fun hashCode(): Int = d.contentHashCode()
}

internal operator fun Int.times(fe: Fe): Fe = fe * this
internal operator fun Int.plus(fe: Fe): Fe = fe + this
internal operator fun Int.minus(fe: Fe): Fe = Fe(this) - fe

private class Jac(val x: Fe, val y: Fe, val z: Fe) {
    fun isInf(): Boolean = z.isZero()

    fun double(): Jac {
        if (isInf()) return this
        val a = x.sqr()
        val b = y.sqr()
        val c = b.sqr()
        val d = (x + b).sqr().minus(a).minus(c).times2()
        val e = a * 3
        val f = e.sqr()
        val x3 = f - d.times2()
        val y3 = e * (d - x3) - c * 8
        val z3 = y.times2() * z
        return Jac(x3, y3, z3)
    }

    operator fun plus(other: Jac): Jac {
        if (isInf()) return other
        if (other.isInf()) return this
        val z1z1 = z.sqr()
        val z2z2 = other.z.sqr()
        val u1 = x * z2z2
        val u2 = other.x * z1z1
        val s1 = y * other.z * z2z2
        val s2 = other.y * z * z1z1
        val h = u2 - u1
        val r = (s2 - s1).times2()
        if (h.isZero()) {
            return if (r.isZero()) double() else INF
        }
        val hh = h.sqr()
        val i = hh * 4
        val j = h * i
        val v = u1 * i
        val x3 = r.sqr() - j - v.times2()
        val y3 = r * (v - x3) - s1.times2() * j
        val z3 = ((z + other.z).sqr() - z1z1 - z2z2) * h
        return Jac(x3, y3, z3)
    }

    fun toGe(): Ge? {
        if (isInf()) return null
        val zi = z.inv()
        val zi2 = zi.sqr()
        return Ge.unchecked(x * zi2, y * zi2 * zi)
    }

    companion object {
        val INF = Jac(Fe.ONE, Fe.ONE, Fe.ZERO)
        fun from(p: Ge) = Jac(p.x, p.y, Fe.ONE)
    }
}

/**
 * secp256k1 group element. Infinity is represented as null.
 */
internal class Ge private constructor(val x: Fe, val y: Fe, check: Boolean) {
    constructor(x: Fe, y: Fe) : this(x, y, true)

    init {
        if (check) {
            check(y.sqr() == x.sqr() * x + Fe(7)) { "point is not on secp256k1" }
        }
    }

    companion object {
        val ORDER_BYTES: ByteArray =
            hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

        val G: Ge = Ge(
            Fe.fromBytes(hexToBytes("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))!!,
            Fe.fromBytes(hexToBytes("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))!!,
        )

        fun unchecked(x: Fe, y: Fe) = Ge(x, y, false)

        fun liftX(x: Fe): Ge? {
            val y = (x.sqr() * x + Fe(7)).sqrt() ?: return null
            return Ge(x, y)
        }

        fun isValidX(x: Fe): Boolean = (x.sqr() * x + Fe(7)).isSquare()
    }

    fun double(): Ge {
        val l = (x.sqr() * 3) / y.times2()
        val x3 = l.sqr() - x.times2()
        val y3 = l * (x - x3) - y
        return Ge.unchecked(x3, y3)
    }

    operator fun plus(other: Ge?): Ge? {
        if (other == null) return this
        return if (x != other.x) {
            val l = (other.y - y) / (other.x - x)
            val x3 = l.sqr() - x - other.x
            val y3 = l * (x - x3) - y
            Ge.unchecked(x3, y3)
        } else if (y == other.y) {
            double()
        } else {
            null
        }
    }

    operator fun times(scalar: ByteArray): Ge? {
        require(scalar.size == 32) { "scalar must be 32 bytes" }
        val pJac = Jac.from(this)
        var q = Jac.INF
        var started = false
        for (byte in scalar) {
            val ub = byte.toInt() and 0xff
            for (s in 7 downTo 0) {
                if (started) q = q.double()
                if (((ub shr s) and 1) != 0) {
                    q = if (!started) pJac else q + pJac
                    started = true
                }
            }
        }
        return q.toGe()
    }
}

internal fun isValidSecretScalar(bytes: ByteArray): Boolean {
    if (bytes.size != 32) return false
    var any = 0
    for (b in bytes) any = any or b.toInt()
    if (any == 0) return false
    for (i in 0..31) {
        val a = bytes.u8(i)
        val b = Ge.ORDER_BYTES.u8(i)
        if (a < b) return true
        if (a > b) return false
    }
    return false
}
