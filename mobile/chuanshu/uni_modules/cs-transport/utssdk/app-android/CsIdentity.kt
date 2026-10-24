package uts.sdk.modules.csTransport

import android.os.Build
import android.util.Base64
import io.dcloud.uts.UTSAndroid
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/** The phone's own key, its fingerprint, and the peers it has pinned - all of it kept in filesDir
 *  and all of it reachable only as JSON strings, so the UTS layer never has to know a Kotlin type.
 *
 *  The key is 32 raw seed bytes, and the arithmetic over it is `Ed25519.kt` rather than
 *  `java.security`: measured on API 34, this platform's provider table has no Ed25519 anywhere
 *  (asking the stripped BouncyCastle or the platform Conscrypt by name both answer `no such algorithm`),
 *  so a `KeyPairGenerator.getInstance("Ed25519")` here is a key that never gets made and a receiver that
 *  never starts. What the key is *for* has not changed - spec §3's signature over the pair message - and
 *  `Ed25519.selfTest()` reproduces the desktop library's own vectors byte for byte.
 *
 *  The certificate on the socket is a separate, RSA-2048 key (`ServedLeaf`), which is why a pair message
 *  from this device carries `tls_fingerprint`. */
object CsIdentity {

    private const val HEX = "0123456789abcdef"

    /** The 32 seed bytes this device signs with. Written next to a copy of the public key in its
     *  SubjectPublicKeyInfo form, because the fingerprint is a digest of those 44 bytes and keeping
     *  them means the digest never depends on a key-encoding round trip. */
    private const val SEED_FILE = "chuanshu-ed25519.seed"
    private const val PUB_FILE = "chuanshu-ed25519.spki"

    /** What a device that ran an older build left behind: the same key, wrapped in PKCS#8 by
     *  `java.security`. Its last 32 bytes are the seed, so the identity survives the move to
     *  `Ed25519.kt` and a peer that pinned this phone yesterday still recognises it. */
    private const val LEGACY_KEY_FILE = "chuanshu-ed25519.pk8"
    private const val ID_FILE = "chuanshu-peer-id.txt"
    private const val TRUST_FILE = "chuanshu-trusted.json"
    private const val PAIRING_FILE = "chuanshu-pairing.json"
    // The receiver's own memories, kept apart from TRUST_FILE on purpose: the one above pins a
    // peer by the address it was met at (this phone dialled out), the ones below say which peers may
    // knock on this phone's door, what is mid-flight, and what already landed. Same digest in the
    // first two, different promises.
    private const val RECEIVER_TRUST_FILE = "chuanshu-receiver-trust.json"
    private const val RECEIVER_OFFERS_FILE = "chuanshu-receiver-offers.json"
    // A finished offer is left out of the resume ledger on purpose, so the receipts need their own file
    // or 收到的文件 only ever remembers this process (task #110).
    private const val RECEIVER_ARRIVALS_FILE = "chuanshu-receiver-arrivals.json"

    private class Self(val peerId: String, val seed: ByteArray, val spki: ByteArray)

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

    /** The 44 bytes an Ed25519 SubjectPublicKeyInfo is: the 12-byte header below then the raw key. The
     *  pair request carries only the last 32 (the PC reads them with
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
        val seedFile = File(dir, SEED_FILE)
        val legacy = File(dir, LEGACY_KEY_FILE)
        val pubFile = File(dir, PUB_FILE)
        val idFile = File(dir, ID_FILE)
        val storedSeed = if (seedFile.exists()) seedFile.readBytes() else null
        val legacyBytes = if (legacy.exists()) legacy.readBytes() else null
        // A PKCS#8 Ed25519 private key is 48 bytes and its last 32 are the seed, so an older build's
        // key can be picked up without ever being parsed.
        val seed = when {
            storedSeed != null && storedSeed.size == 32 -> storedSeed
            legacyBytes != null && legacyBytes.size == 48 -> legacyBytes.copyOfRange(16, 48)
            else -> ByteArray(32).also { SecureRandom().nextBytes(it) }
        }
        val raw = Ed25519.publicKey(seed)
        // The stored SPKI is only kept when it is still this seed's key; anything else - a half-written
        // file, a build that made the key somewhere else - is replaced rather than trusted.
        val storedSpki = if (pubFile.exists()) pubFile.readBytes() else null
        val keep = storedSpki != null && storedSpki.size == 44 &&
            storedSpki.copyOfRange(12, 44).contentEquals(raw)
        val spki = if (keep) storedSpki!! else SPKI_HEAD + raw
        if (!keep) pubFile.writeBytes(spki)
        if (storedSeed == null || !storedSeed.contentEquals(seed)) seedFile.writeBytes(seed)
        val peerId = if (idFile.exists()) idFile.readText().trim() else ""
        val made = Self(if (peerId.length == 32) peerId else newPeerId(), seed, spki)
        if (peerId != made.peerId) idFile.writeText(made.peerId)
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
        JSONObject()
            .put("public_key", Base64.encodeToString(rawOf(me.spki), Base64.NO_WRAP))
            .put("signature", Base64.encodeToString(
                Ed25519.sign(me.seed, message.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP))
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

    private fun readText(name: String): String {
        val dir = filesDir() ?: return ""
        return try {
            val f = File(dir, name)
            if (f.exists()) f.readText() else ""
        } catch (e: Throwable) {
            ""
        }
    }

    private fun writeText(name: String, text: String): Boolean {
        val dir = filesDir() ?: return false
        return try {
            File(dir, name).writeText(text)
            true
        } catch (e: Throwable) {
            false
        }
    }

    // -------------------------------------------------- the receiver's own memories

    /** Who may send to this phone, and which offers this inbox already took - verbatim the text
     *  cs-receive.uts serialises with trustJson() and stateAll(). Neither one survives a restart on
     *  its own, and losing them is not cosmetic: the peer that pinned its key is refused and a person
     *  is asked to type a code whose entire job is to be typed once, while 收到的文件 goes empty over
     *  a folder that is still full. Android is the last host that had no copy of these files at all
     *  (Harmony got them in #80, iOS in #81, this is #86). */
    fun loadTrustPeers(): String = readText(RECEIVER_TRUST_FILE)

    fun saveTrustPeers(text: String): Boolean = writeText(RECEIVER_TRUST_FILE, text)

    fun loadOfferStates(): String = readText(RECEIVER_OFFERS_FILE)

    fun saveOfferStates(text: String): Boolean = writeText(RECEIVER_OFFERS_FILE, text)

    fun loadArrivalStates(): String = readText(RECEIVER_ARRIVALS_FILE)

    fun saveArrivalStates(text: String): Boolean = writeText(RECEIVER_ARRIVALS_FILE, text)

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

    /** The 12 bytes in front of every Ed25519 SubjectPublicKeyInfo: SEQUENCE{ SEQUENCE{
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
        Ed25519.verify(rawOf(spki), message.toByteArray(Charsets.UTF_8),
            Base64.decode(signatureB64, Base64.DEFAULT))
    } catch (e: Throwable) {
        false
    }
}
