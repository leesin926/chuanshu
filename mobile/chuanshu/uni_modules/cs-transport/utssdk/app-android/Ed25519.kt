package uts.sdk.modules.csTransport

import java.math.BigInteger
import java.security.MessageDigest

/** Ed25519 (RFC 8032) on BigInteger, because the framework on this device does not have it.
 *
 *  Measured on the API 34 emulator: the provider table is
 *  `AndroidNSSP AndroidOpenSSL CertPathProvider AndroidKeyStoreBCWorkaround BC/1.68 HarmonyJSSE
 *  AndroidKeyStore`, and asking the two candidates by name - the platform Conscrypt
 *  (`AndroidOpenSSL`) and the platform's stripped BouncyCastle (`BC`) - answers `no such algorithm`
 *  for Ed25519 and for EdDSA. So this is not a fallback-order artifact and not a standard-base
 *  artifact: the JCA here has no Ed25519 to be found.
 *
 *  Shipping bcprov inside the plugin was the other way, and it is closed for a different reason - a
 *  UTS plugin's native dependencies do not load in the standard base, so it could not be tested here
 *  at all. This file is arithmetic on BigInteger plus SHA-512, both of which the platform does have.
 *
 *  `selfTest()` runs against vectors produced by the same library the PC signs with
 *  (`cryptography`'s Ed25519), so reproducing them here means the phone and the desktop agree by
 *  construction rather than by two readings of the same RFC. */
object Ed25519 {

    private val TWO = BigInteger.valueOf(2)
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

    /** The order of the base point, written as the hex the RFC prints rather than as decimal digits -
     *  the decimal form of this was transcribed once, 180 off, and every signature it made was wrong
     *  while every public key stayed right, because key generation never reduces modulo L.
     *  `selfTest()` re-checks it by multiplying the base point by L and demanding the identity. */
    private val L: BigInteger = BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

    /** d = -121665/121666, the curve's own parameter. */
    private val D: BigInteger =
        BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)

    /** sqrt(-1) = 2^((p-1)/4). Checked by squaring it, not by trusting the exponent: the neighbouring
     *  (p+3)/8 and (p+5)/8 are the exponents the square-root step below uses, and neither of those
     *  squares to -1. */
    private val SQRT_M1: BigInteger = TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)

    /** Extended twisted-Edwards coordinates: x = X/Z, y = Y/Z, xy = T/Z. */
    private class Ge(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    private val IDENTITY = Ge(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    /** The base point: y = 4/5 and the x recovered from it whose encoding carries no sign bit. */
    private val BASE: Ge = run {
        val y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P)
        val x = recoverX(y, BigInteger.ZERO) ?: throw IllegalStateException("基址算不出来")
        Ge(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    /** x² = (y²-1)/(dy²+1), taken as e^((p+3)/8) and corrected by sqrt(-1) when that is not a root.
     *  `odd` is the bit the encoding put next to y. */
    private fun recoverX(y: BigInteger, odd: BigInteger): BigInteger? {
        val y2 = y.multiply(y).mod(P)
        val num = y2.subtract(BigInteger.ONE)
        val den = D.multiply(y2).add(BigInteger.ONE).mod(P)
        if (den.signum() == 0) return null
        val e = num.multiply(den.modInverse(P)).mod(P)
        var x = e.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
        if (x.multiply(x).mod(P).subtract(e).mod(P).signum() != 0) {
            x = x.multiply(SQRT_M1).mod(P)
        }
        if (x.multiply(x).mod(P).subtract(e).mod(P).signum() != 0) return null
        if (x.signum() == 0 && odd.signum() != 0) return null
        if ((if (x.testBit(0)) BigInteger.ONE else BigInteger.ZERO) != odd) return P.subtract(x)
        return x
    }

    /** The complete addition law (add-2008-hwcd-3): the same formula adds and doubles, which is why
     *  the loop below needs no special case and no identity check. */
    private fun add(p: Ge, q: Ge): Ge {
        val a = p.y.subtract(p.x).multiply(q.y.subtract(q.x)).mod(P)
        val b = p.y.add(p.x).multiply(q.y.add(q.x)).mod(P)
        val c = p.t.multiply(q.t).multiply(TWO).multiply(D).mod(P)
        val dd = p.z.multiply(q.z).multiply(TWO).mod(P)
        val e = b.subtract(a)
        val f = dd.subtract(c)
        val g = dd.add(c)
        val h = b.add(a)
        return Ge(e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P))
    }

    private fun multiply(k: BigInteger, point: Ge): Ge {
        var result = IDENTITY
        var base = point
        var n = k
        while (n.signum() > 0) {
            if (n.testBit(0)) result = add(result, base)
            base = add(base, base)
            n = n.shiftRight(1)
        }
        return result
    }

    private fun le32(value: BigInteger): ByteArray {
        val out = ByteArray(32)
        var n = value.mod(P)
        for (i in 0 until 32) {
            out[i] = n.and(BigInteger.valueOf(0xff)).toByte()
            n = n.shiftRight(8)
        }
        return out
    }

    private fun reverseOf(bytes: ByteArray): ByteArray {
        val out = bytes.copyOf()
        out.reverse()
        return out
    }

    private fun encode(p: Ge): ByteArray {
        val zi = p.z.modInverse(P)
        val x = p.x.multiply(zi).mod(P)
        val y = p.y.multiply(zi).mod(P)
        val out = le32(y)
        if (x.testBit(0)) out[31] = (out[31].toInt() or 0x80).toByte()
        return out
    }

    private fun decode(point: ByteArray): Ge? {
        if (point.size != 32) return null
        val copy = point.copyOf()
        val odd = if ((copy[31].toInt() shr 7) and 1 == 1) BigInteger.ONE else BigInteger.ZERO
        copy[31] = (copy[31].toInt() and 0x7f).toByte()
        val y = BigInteger(1, reverseOf(copy))
        if (y >= P) return null
        val x = recoverX(y, odd) ?: return null
        return Ge(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    private fun sha512(parts: Array<ByteArray>): ByteArray {
        val md = MessageDigest.getInstance("SHA-512")
        for (part in parts) md.update(part)
        return md.digest()
    }

    private fun scalarLE(bytes: ByteArray): BigInteger = BigInteger(1, reverseOf(bytes)).mod(L)

    /** The seed expanded the way §5.1.5 says: the clamped low half is the scalar, the high half is
     *  the prefix that blinds the random point, so the signature stays deterministic. */
    private class Expanded(val scalar: BigInteger, val prefix: ByteArray, val public: ByteArray)

    private fun expand(seed: ByteArray): Expanded {
        if (seed.size != 32) throw IllegalArgumentException("种子要 32 字节")
        val h = sha512(arrayOf(seed))
        val low = h.copyOfRange(0, 32)
        low[0] = (low[0].toInt() and 0xf8).toByte()
        low[31] = (low[31].toInt() and 0x7f).toByte()
        low[31] = (low[31].toInt() or 0x40).toByte()
        val scalar = BigInteger(1, reverseOf(low))
        return Expanded(scalar, h.copyOfRange(32, 64), encode(multiply(scalar, BASE)))
    }

    fun publicKey(seed: ByteArray): ByteArray = expand(seed).public

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        val key = expand(seed)
        val r = scalarLE(sha512(arrayOf(key.prefix, message)))
        val bigR = encode(multiply(r, BASE))
        val k = scalarLE(sha512(arrayOf(bigR, key.public, message)))
        val s = k.multiply(key.scalar).add(r).mod(L)
        return bigR + le32(s)
    }

    /** [S]B == R + [k]A, with the encodings compared at the end. A point that does not decode, an
     *  S of L or more, or a signature of any length but 64 all answer false rather than throwing:
     *  the caller reads this as "that is not your peer", and it is. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        return try {
            val a = decode(publicKey) ?: return false
            val bigR = decode(signature.copyOfRange(0, 32)) ?: return false
            val s = BigInteger(1, reverseOf(signature.copyOfRange(32, 64)))
            if (s >= L) return false
            val k = scalarLE(sha512(arrayOf(signature.copyOfRange(0, 32), publicKey, message)))
            encode(multiply(s, BASE)).contentEquals(encode(add(bigR, multiply(k, a))))
        } catch (e: Throwable) {
            false
        }
    }

    // ---------------------------------------------------------------------- self-test

    private fun bytesOf(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    private fun hexOf(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 0x0f])
        }
        return out.toString()
    }

    /** seed / message / public / signature, the last two made by the PC's own Ed25519 library. */
    private val VECTORS = arrayOf(
        arrayOf(
            "9d61b19deffd5a60ba900af86043ef5592ede99b0032a674a7a98bb0f9f8f2e2", "",
            "7b0374a6cd2d10ba1430e1200fddf0dbc3830cb0f20bb0649531f284ed3e4a39",
            "4b2704308bf576e9b42961c04f629a6d59fcff867f09ea4cba7cc4e22032a05689e401235434a42134a9fe951077400b3f39a67f6f539b08cfb9088ce8ab4b00"
        ),
        arrayOf(
            "4ccd089b28ff96da9db6c346ec114e0f5b8b319f35aba624da8cf6ed4fb8a6fb", "72",
            "998b0ee15d778c10edb92fd09a76b5cfeea085e81bbb0504d69481dda860fb9c",
            "852cf4320548f1462ebde5bea6012ec05e3693f101e47e368cd8db6c97efcb9dc68f0b435de51c721b9525f12f1dba3994ac88b744e3d44aa2ce08b8eac26305"
        ),
        arrayOf(
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead", "74657374206d657373616765",
            "3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06",
            "fb8d232b877ec9b4598d09667c62af3fb50e6bdca35d2b6514f7a4629834d6566e5225522582acf76b5c9911aacd66ec91ead6fd9c89bb8ff8587d4907dcb00d"
        )
    )

    /** One line per vector plus the round trip and a tampered check, so a wrong transcription says
     *  which step broke. Runs in milliseconds; nothing here is timed against a socket. */
    fun selfTest(): String {
        val out = StringBuilder()
        out.append("order kills the base point: ")
            .append(encode(multiply(L, BASE)).contentEquals(encode(IDENTITY))).append('\n')
        out.append("sqrt(-1) squares to -1: ")
            .append(SQRT_M1.multiply(SQRT_M1).mod(P) == P.subtract(BigInteger.ONE)).append('\n')
        for (case in VECTORS) {
            val seed = bytesOf(case[0])
            val message = bytesOf(case[1])
            val made = try {
                publicKey(seed)
            } catch (e: Throwable) {
                out.append("keygen threw: ").append(e.toString()).append('\n')
                continue
            }
            out.append("pub matches vector: ").append(hexOf(made) == case[2]).append('\n')
            if (case[3].length != 128) continue
            val sig = sign(seed, message)
            out.append("sig matches vector: ").append(hexOf(sig) == case[3]).append('\n')
            out.append("vector verifies: ")
                .append(verify(made, message, bytesOf(case[3]))).append('\n')
        }
        val seed = ByteArray(32) { (it * 7 + 3).toByte() }
        val pub = publicKey(seed)
        val msg = "chuanshu-pair-message".toByteArray(Charsets.UTF_8)
        val sig = sign(seed, msg)
        out.append("round trip: ").append(verify(pub, msg, sig)).append('\n')
        val wrong = sig.copyOf()
        wrong[0] = (wrong[0].toInt() xor 0x01).toByte()
        out.append("tampered signature refused: ").append(!verify(pub, msg, wrong)).append('\n')
        val other = ByteArray(32) { (it * 7 + 4).toByte() }
        out.append("stranger refused: ").append(!verify(publicKey(other), msg, sig)).append('\n')
        out.append("sig bytes=").append(sig.size).append(" pub bytes=").append(pub.size).append('\n')
        return out.toString()
    }
}
