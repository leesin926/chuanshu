package uts.sdk.modules.csTransport

import android.os.Build
import android.util.Base64
import io.dcloud.uts.UTSAndroid
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** The phone's own key, its fingerprint, and the peers it has pinned - all of it kept in filesDir
 *  and all of it reachable only as JSON strings, so the UTS layer never has to know a Kotlin type.
 *
 *  Why this half is Kotlin and not UTS: `Signature.getInstance("Ed25519")` and the SPKI digest are
 *  java.security calls that UTS can make, but the key has to survive an app restart for spec §3's
 *  signature-only re-pair to mean anything, and that file handling reads better here. */
object CsIdentity {

    private const val HEX = "0123456789abcdef"

    /** PKCS#8 DER of the private key and SubjectPublicKeyInfo DER of the public one, as
     *  java.security writes them. The SPKI file is what the fingerprint is computed over, so
     *  keeping both makes the digest reproducible without a KeyFactory round trip. */
    private const val KEY_FILE = "chuanshu-ed25519.pk8"
    private const val PUB_FILE = "chuanshu-ed25519.spki"
    private const val ID_FILE = "chuanshu-peer-id.txt"
    private const val TRUST_FILE = "chuanshu-trusted.json"
    private const val PAIRING_FILE = "chuanshu-pairing.json"

    private class Self(val peerId: String, val key: PrivateKey, val spki: ByteArray)

    private var cached: Self? = null

    private fun hexOf(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(HEX[v shr 4]).append(HEX[v and 0x0f])
        }
        return out.toString()
    }

    private fun fail(why: String): String = JSONObject().put("error", why).toString()

    private fun filesDir(): File? = UTSAndroid.getAppContext()?.filesDir

    /** The 44 bytes a SunEC/Conscrypt Ed25519 public key encodes to: 12-byte header then the raw
     *  key. The pair request carries only the last 32 (the PC reads them with
     *  `Ed25519PublicKey.from_public_bytes`), while the fingerprint is over the whole 44 - the same
     *  two values app/net/identity.py computes. */
    private fun rawOf(spki: ByteArray): ByteArray =
        if (spki.size == 44) spki.copyOfRange(12, 44) else spki

    private fun fingerprintOf(spki: ByteArray): String =
        hexOf(MessageDigest.getInstance("SHA-256").digest(spki))

    private fun newPeerId(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return hexOf(bytes)
    }

    private fun loadOrMake(): Self {
        cached?.let { return it }
        val dir = filesDir() ?: throw IllegalStateException("拿不到应用私有目录")
        val keyFile = File(dir, KEY_FILE)
        val pubFile = File(dir, PUB_FILE)
        val idFile = File(dir, ID_FILE)
        if (keyFile.exists() && pubFile.exists()) {
            val spec = PKCS8EncodedKeySpec(keyFile.readBytes())
            val key = KeyFactory.getInstance("Ed25519").generatePrivate(spec)
            val spki = pubFile.readBytes()
            val peerId = if (idFile.exists()) idFile.readText().trim() else newPeerId()
            val made = Self(if (peerId.length == 32) peerId else newPeerId(), key, spki)
            cached = made
            return made
        }
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val spki = pair.public.encoded
        keyFile.writeBytes(pair.private.encoded)
        pubFile.writeBytes(spki)
        val made = Self(newPeerId(), pair.private, spki)
        idFile.writeText(made.peerId)
        cached = made
        return made
    }

    private fun deviceName(): String {
        val maker = Build.MANUFACTURER.orEmpty()
        val model = Build.MODEL.orEmpty()
        val named = if (model.contains(maker, true)) model else "$maker $model".trim()
        return if (named.isEmpty()) "Android 手机" else "手机 · $named"
    }

    /** {"peer_id","name","fingerprint"} - or {"error"} if this device cannot make an Ed25519 key. */
    fun self(): String = try {
        val me = loadOrMake()
        JSONObject()
            .put("peer_id", me.peerId)
            .put("name", deviceName())
            .put("fingerprint", fingerprintOf(me.spki))
            .toString()
    } catch (e: Throwable) {
        fail("本机密钥不可用：" + e)
    }

    /** The pair request's two crypto fields: base64 raw key and a signature over whatever bytes the
     *  caller hands it. Which message that is belongs to spec §3 and to cs-protocol.uts, not here -
     *  the fourth field appears only when the served leaf is not this key. */
    fun signMessage(message: String): String = try {
        val me = loadOrMake()
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(me.key)
        signer.update(message.toByteArray(Charsets.UTF_8))
        JSONObject()
            .put("public_key", Base64.encodeToString(rawOf(me.spki), Base64.NO_WRAP))
            .put("signature", Base64.encodeToString(signer.sign(), Base64.NO_WRAP))
            .toString()
    } catch (e: Throwable) {
        fail("配对签名失败：" + e)
    }

    fun fingerprint(): String = try {
        fingerprintOf(loadOrMake().spki)
    } catch (e: Throwable) {
        ""
    }

    // ------------------------------------------------------------------ trust store

    private fun trustFile(): File? = filesDir()?.let { File(it, TRUST_FILE) }

    private fun readTrust(): JSONArray {
        val f = trustFile() ?: return JSONArray()
        if (!f.exists()) return JSONArray()
        return try {
            JSONArray(f.readText())
        } catch (e: Throwable) {
            JSONArray()
        }
    }

    private fun writeTrust(list: JSONArray): Boolean = try {
        trustFile()?.writeText(list.toString())
        true
    } catch (e: Throwable) {
        false
    }

    // ------------------------------------------------------------- pairing material

    private fun pairingFile(): File? = filesDir()?.let { File(it, PAIRING_FILE) }

    /** The document cs-receive.uts produced for this device's code and passphrase, or "" when there
     *  is none yet. It lives beside the key for the same reason: a pairing text somebody already
     *  read has to still mean the same thing after a restart. */
    fun loadPairing(): String = try {
        val f = pairingFile()
        if (f == null || !f.exists()) "" else f.readText()
    } catch (e: Throwable) {
        ""
    }

    fun savePairing(text: String): Boolean = try {
        pairingFile()?.writeText(text)
        true
    } catch (e: Throwable) {
        false
    }

    /** Pin a peer by the fingerprint its TLS certificate presented, tagged with the address it was
     *  met at. peer_id is metadata only, exactly like the PC side: the digest is the anchor. */
    fun pin(host: String, port: Number, fingerprint: String, peerId: String, name: String): String {
        if (fingerprint.length != 64) return fail("指纹不是完整的 64 位十六进制，没有固定")
        val list = readTrust()
        var replaced = false
        for (i in 0 until list.length()) {
            val entry = list.optJSONObject(i) ?: continue
            if (entry.optString("fingerprint") == fingerprint) {
                entry.put("host", host).put("port", port.toInt()).put("peer_id", peerId).put("name", name)
                replaced = true
            }
        }
        if (!replaced) {
            list.put(JSONObject()
                .put("fingerprint", fingerprint)
                .put("host", host).put("port", port.toInt()).put("peer_id", peerId).put("name", name))
        }
        return if (writeTrust(list)) JSONObject().put("count", list.length()).toString()
        else fail("固定指纹写不进本机存储")
    }

    /** What we already know about this address. Non-empty means the transport must refuse any peer
     *  there that presents a different key - the hand-typed-address half of TOFU. */
    fun pinFor(host: String, port: Number): String {
        val list = readTrust()
        for (i in 0 until list.length()) {
            val entry = list.optJSONObject(i) ?: continue
            if (entry.optString("host") == host && entry.optInt("port") == port.toInt()) {
                return entry.optString("fingerprint")
            }
        }
        return ""
    }

    /** Forget the pin for one address so the next connection is a fresh first contact. */
    fun unpin(host: String, port: Number): String {
        val list = readTrust()
        val kept = JSONArray()
        var dropped = 0
        for (i in 0 until list.length()) {
            val entry = list.optJSONObject(i) ?: continue
            if (entry.optString("host") == host && entry.optInt("port") == port.toInt()) dropped++
            else kept.put(entry)
        }
        if (dropped == 0) return JSONObject().put("dropped", 0).toString()
        return if (writeTrust(kept)) JSONObject().put("dropped", dropped).toString()
        else fail("解除固定没能写进本机存储")
    }

    // -------------------------------------------------------------- reading another key

    /** The 12 bytes SunEC puts in front of every Ed25519 SubjectPublicKeyInfo: SEQUENCE{ SEQUENCE{
     *  OID 1.3.101.112 }, BIT STRING(32) }. A pair request carries only the raw 32 after it, so the
     *  prefix is rebuilt here - the same reconstruction app/net/identity.py:_spki_der does, which is
     *  what makes both ends agree on one digest. */
    private val SPKI_HEAD = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    )

    private fun spkiOf(publicKeyB64: String): ByteArray? {
        val got = try {
            Base64.decode(publicKeyB64, Base64.DEFAULT)
        } catch (e: Throwable) {
            return null
        }
        if (got.size == 44) return got
        if (got.size != 32) return null
        return SPKI_HEAD + got
    }

    /** hex SHA-256 of the peer's SPKI, or '' when the request carried something that is not a key.
     *  The whole trust model hangs on this one value, so a bad key has to read as "no fingerprint"
     *  rather than as a digest of garbage. */
    fun fpOfKeyB64(publicKeyB64: String): String = try {
        val spki = spkiOf(publicKeyB64) ?: return ""
        hexOf(MessageDigest.getInstance("SHA-256").digest(spki))
    } catch (e: Throwable) {
        ""
    }

    /** Proof that the peer holds the private half of the key it just offered: verify a signature over
     *  the message the caller hands in. This is what lets a pinned peer re-pair with an empty code. */
    fun verifyKey(publicKeyB64: String, message: String, signatureB64: String): Boolean = try {
        val spki = spkiOf(publicKeyB64) ?: return false
        val pub = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
        val checker = Signature.getInstance("Ed25519")
        checker.initVerify(pub)
        checker.update(message.toByteArray(Charsets.UTF_8))
        checker.verify(Base64.decode(signatureB64, Base64.DEFAULT))
    } catch (e: Throwable) {
        false
    }

    // -------------------------------------------------------------- our own certificate

    private const val CERT_FILE = "chuanshu-ed25519.crt"
    private const val OID_ED25519 = "06032b6570"
    private const val OID_CN = "0603550403"

    /** The key the certificate below signs with. Kept off the UTS boundary on purpose: a PrivateKey
     *  that reaches UTS is a PrivateKey that can be forgotten about in a later refactor. */
    fun privateKey(): PrivateKey = loadOrMake().key

    fun spki(): ByteArray = loadOrMake().spki

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

    private fun derTime(millis: Long): ByteArray {
        val f = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US)
        f.timeZone = TimeZone.getTimeZone("UTC")
        return der(0x17, f.format(Date(millis)).toByteArray(Charsets.US_ASCII))
    }

    /** A self-signed certificate around the key this device already had.
     *
     *  Hand-built because the only other way to get one on Android is a BouncyCastle dependency this
     *  machine cannot verify from a mirror, and because the SPKI inside it has to be the exact bytes
     *  `fingerprint()` hashes: the PC pins that digest, so a certificate whose key differed from the
     *  one in the pair request would look like an attack on our own protocol. */
    private fun buildCert(peerId: String, key: PrivateKey, spki: ByteArray): ByteArray {
        val serial = BigInteger(64, SecureRandom())
        val now = System.currentTimeMillis()
        val notAfter = Calendar.getInstance().apply {
            timeInMillis = now
            add(Calendar.YEAR, 3650)
        }.timeInMillis
        val alg = derSeq(derOid(OID_ED25519))
        val tbs = derSeq(
            der(0xa0, der(0x02, BigInteger.valueOf(2).toByteArray())),
            der(0x02, serial.toByteArray()),
            alg,
            derName(peerId),
            derSeq(derTime(now - 86400000L), derTime(notAfter)),
            derName(peerId),
            spki
        )
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(key)
        signer.update(tbs)
        // BIT STRING: one leading unused-bits byte, always zero for Ed25519.
        return derSeq(tbs, alg, der(0x03, byteArrayOf(0) + signer.sign()))
    }

    private fun parseCert(der: ByteArray): X509Certificate? = try {
        CertificateFactory.getInstance("X.509")
            .generateCertificate(java.io.ByteArrayInputStream(der)) as X509Certificate
    } catch (e: Throwable) {
        null
    }

    /** Our certificate, made once and then reused: a peer that pinned us yesterday has to see the same
     *  bytes tomorrow, and an expired or key-mismatched file is silently rebuilt.
     *
     *  Thrown at the caller rather than answered with an empty array: the listener cannot start without
     *  it, and "keystore has no key entry" is a worse message than the real reason. */
    @Synchronized
    fun certDer(): ByteArray {
        val me = loadOrMake()
        val want = fingerprintOf(me.spki)
        val file = filesDir()?.let { File(it, CERT_FILE) } ?: throw IllegalStateException("拿不到应用私有目录")
        if (file.exists()) {
            val stored = file.readBytes()
            val parsed = parseCert(stored)
            if (parsed != null) {
                val same = try {
                    parsed.checkValidity()
                    want.equals(hexOf(MessageDigest.getInstance("SHA-256").digest(parsed.publicKey.encoded)), true)
                } catch (e: Throwable) {
                    false
                }
                if (same) return stored
            }
        }
        val made = buildCert(me.peerId, me.key, me.spki)
        val parsed = parseCert(made) ?: throw IllegalStateException("本机证书没能被系统解析：" + made.size + " 字节")
        parsed.checkValidity()
        file.writeBytes(made)
        return made
    }
}
