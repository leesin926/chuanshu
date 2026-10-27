package uts.sdk.modules.csTransport

import android.util.Log
import io.dcloud.uts.UTSAndroid
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** The certificate this phone hands out on the socket, and the private key that goes with it.
 *
 *  It is RSA-2048 rather than the device's own Ed25519 identity for the reason measured on Harmony
 *  (task #47) and now on Android (task #106): the identity key here is not a `java.security` key at all
 *  - the platform has no Ed25519 to make one - so there is nothing for a keystore entry to hold. That
 *  split is what contract §3's `tls_fingerprint` field exists to say out loud: a pair message signed by
 *  the Ed25519 identity names the leaf that the socket will present, so a peer pins one number and knows
 *  what to expect from the other. Two digests per device, one trust decision.
 *
 *  Built by hand for the same reason the old Ed25519 certificate was: the only other way to get a
 *  self-signed certificate on Android is a BouncyCastle dependency, and a dependency fetched from a
 *  mirror cannot be verified here. */
object ServedLeaf {

    private const val CERT_FILE = "chuanshu-tls-rsa.crt"
    private const val PRI_FILE = "chuanshu-tls-rsa.pk8"
    private const val SPKI_FILE = "chuanshu-tls-rsa.spki"

    /** Why a stored leaf was thrown away. Without this the rebuild is silent, and a peer that pinned
     *  this phone finds out on its own restart that the number it saved does not describe it any more. */
    private const val TAG = "cs-leaf"

    /** 1.2.840.113549.1.1.11 with the RSA parameters, as the DER bytes of the OID plus a NULL. */
    private val ALG_RSA_SHA256: ByteArray =
        derSeq(derOid("06092a864886f70d01010b") + byteArrayOf(0x05, 0x00))
    private const val OID_CN = "0603550403"

    private class Leaf(val key: PrivateKey, val spki: ByteArray, val der: ByteArray, val fp: String)

    private var cached: Leaf? = null

    private fun hexOf(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 0x0f])
        }
        return out.toString()
    }

    private fun filesDir(): File? = UTSAndroid.getAppContext()?.filesDir

    private fun der(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val head = when {
            n < 0x80 -> byteArrayOf(tag.toByte(), n.toByte())
            n < 0x100 -> byteArrayOf(tag.toByte(), 0x81.toByte(), n.toByte())
            else -> byteArrayOf(tag.toByte(), 0x82.toByte(), (n shr 8).toByte(), (n and 0xff).toByte())
        }
        return head + body
    }

    private fun concatAll(parts: Array<out ByteArray>): ByteArray {
        val sink = ByteArrayOutputStream()
        for (part in parts) sink.write(part, 0, part.size)
        return sink.toByteArray()
    }

    private fun derSeq(vararg parts: ByteArray): ByteArray = der(0x30, concatAll(parts))
    private fun derSet(vararg parts: ByteArray): ByteArray = der(0x31, concatAll(parts))

    private fun derOid(hex: String): ByteArray {
        val bytes = ByteArray(hex.length / 2)
        for (i in bytes.indices) bytes[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return bytes
    }

    private fun derName(cn: String): ByteArray =
        derSeq(derSet(derSeq(derOid(OID_CN), der(0x0c, cn.toByteArray(Charsets.UTF_8)))))

    /** UTCTime carries a two-digit year, and RFC 5280 reads 00-69 as 2000-2069 and 70-99 as 1970-1999.
     *  A notAfter outside that window is therefore not a far-future date at all: measured on this
     *  emulator, "+3650 years" came back as `Certificate expired at ... 1976`, which made the stored
     *  leaf look spent and rebuilt it - and a rebuilt leaf means a new SPKI digest, so every peer that
     *  pinned this phone silently lost its pin on the phone's next restart. */
    private fun derTime(millis: Long): ByteArray {
        val f = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US)
        f.timeZone = TimeZone.getTimeZone("UTC")
        return der(0x17, f.format(Date(millis)).toByteArray(Charsets.US_ASCII))
    }

    /** §1 says the service leaf carries CN=peer_id, and the PC's and Harmony's both do. Nothing on the
     *  wire reads a subject - a peer names this device from the pair request - but the leaf is written
     *  down once and the subject is the one part of it a log shows, so this end answered with the
     *  hardware name while the other two answered with the id. The hardware name stays only as the
     *  answer when the identity layer itself cannot speak. */
    private fun commonName(): String = CsIdentity.peerId().ifEmpty { CsIdentity.hardwareName() }

    private fun parseCert(der: ByteArray): X509Certificate? = try {
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    } catch (e: Throwable) {
        null
    }

    private fun build(): Leaf {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val spki = pair.public.encoded
        val now = System.currentTimeMillis()
        val notAfter = Calendar.getInstance().apply {
            timeInMillis = now
            add(Calendar.YEAR, 20)
        }.timeInMillis
        val tbs = derSeq(
            der(0xa0, der(0x02, BigInteger.valueOf(2).toByteArray())),
            der(0x02, BigInteger(64, SecureRandom()).toByteArray()),
            ALG_RSA_SHA256,
            derName(commonName()),
            derSeq(derTime(now - 86400000L), derTime(notAfter)),
            derName(commonName()),
            spki
        )
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(pair.private)
        signer.update(tbs)
        // BIT STRING: one leading unused-bits byte, always zero for a whole number of bytes.
        return Leaf(pair.private, spki, derSeq(tbs, ALG_RSA_SHA256, der(0x03, byteArrayOf(0) + signer.sign())),
            hexOf(MessageDigest.getInstance("SHA-256").digest(spki)))
    }

    private fun stored(dir: File): Leaf? {
        val certFile = File(dir, CERT_FILE)
        val pri = File(dir, PRI_FILE)
        val spkiFile = File(dir, SPKI_FILE)
        if (!certFile.exists() || !pri.exists() || !spkiFile.exists()) return null
        val der = certFile.readBytes()
        val spkiBytes = spkiFile.readBytes()
        val parsed = parseCert(der)
        if (parsed == null) {
            Log.w(TAG, "stored cert does not parse: " + der.size + " bytes")
            return null
        }
        // The dates are not read, on purpose: §1 mints this leaf once and says a device that ends up
        // with a different leaf has to be re-paired by hand (the pins are on the certificate). Asking
        // the clock whether the stored one is still current turns a backward-set clock into a new key
        // pair, a new SPKI digest, and every peer that pinned this phone silently losing its pin on the
        // next restart - which is exactly what the note on derTime measured once already. The PC keeps
        // a leaf whose files exist; Harmony reads the bytes back and never looks at the dates.
        val key = try {
            KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pri.readBytes()))
        } catch (e: Throwable) {
            Log.w(TAG, "stored key does not parse: $e")
            return null
        }
        // Not a byte comparison of the two encodings: the socket presents the certificate, so the bytes a
        // peer digests are the ones embedded in it, and a platform that re-encodes an RSA public key on
        // parse (AlgorithmIdentifier NULL parameters in or out) would otherwise throw away a leaf that is
        // exactly the one it has always served - and every peer's pin would break on a restart.
        val pub = parsed.publicKey
        if (pub !is RSAPublicKey || key !is RSAPrivateKey || pub.modulus != key.modulus) {
            Log.w(TAG, "stored cert and key are not a pair")
            return null
        }
        return Leaf(key, spkiBytes, der, hexOf(MessageDigest.getInstance("SHA-256").digest(spkiBytes)))
    }

    /** The leaf, made once and then kept: a peer that pinned this address has to see the same bytes
     *  tomorrow, so only a file that does not parse or a cert whose key is gone gets rebuilt - never a
     *  date. Rebuilding is the loud half of losing every peer's pin, and it is not a thing this function
     *  is allowed to decide on its own. Thrown at the caller rather than answered with an empty key:
     *  the listener cannot start without it. */
    @Synchronized
    private fun leaf(): Leaf {
        cached?.let { return it }
        val dir = filesDir() ?: throw IllegalStateException("拿不到应用私有目录")
        val got = stored(dir) ?: build().also {
            File(dir, CERT_FILE).writeBytes(it.der)
            File(dir, PRI_FILE).writeBytes(it.key.encoded)
            File(dir, SPKI_FILE).writeBytes(it.spki)
        }
        cached = got
        return got
    }

    fun certDer(): ByteArray = leaf().der

    fun privateKey(): PrivateKey = leaf().key

    /** The number a pair message declares as `tls_fingerprint`, and the one the peer expects to see on
     *  this socket. '' only when the key was never made, which is a broken receiver, not a peer without
     *  a certificate. */
    fun fingerprint(): String = try {
        leaf().fp
    } catch (e: Throwable) {
        ""
    }
}
