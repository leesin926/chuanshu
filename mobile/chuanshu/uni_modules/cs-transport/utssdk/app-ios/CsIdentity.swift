import Foundation
import UIKit
import CryptoKit
import Security

/** The iPhone's own key, its fingerprint, the peers it has pinned, and the certificate its listener
 *  answers under - all of it reached only as JSON text and `Data`, so the UTS layer never has to know a
 *  Swift type.
 *
 *  Two keys live here, on purpose. The first is the identity: an Ed25519 key whose SPKI digest is what
 *  a peer pins and what `pair_message` signs - the same kind of key the desktop and the other phones
 *  hold, so one device means one number across all of them. The second exists only because nothing in
 *  the keychain can hold an Ed25519 *private* key: `SecKeyCreateRandomKey` offers RSA and EC, and a TLS
 *  listener needs a `SecIdentity`, which needs a keychain key. So the socket answers under a RSA-2048
 *  leaf and the pair message says both numbers - §3's fourth field, the one Harmony's receiver already
 *  uses for exactly this reason.
 *
 *  One lock covers this whole file, and it is recursive because the paths nest: `certificate()` holds it
 *  while asking for the peer id, which reads the signing key, which wants it too. */
public enum CsIdentity {

    private static let SEED_FILE = "chuanshu-ed25519.seed"
    private static let PUB_FILE = "chuanshu-ed25519.spki"
    private static let ID_FILE = "chuanshu-peer-id.txt"
    private static let TRUST_FILE = "chuanshu-trusted.json"
    private static let PAIRING_FILE = "chuanshu-pairing.json"
    /** The receiver's two other memories, as the documents cs-receive.uts serialises: which peers may
     *  send here, and which offers this inbox already took. */
    private static let PEERS_FILE = "chuanshu-receiver-trust.json"
    private static let OFFERS_FILE = "chuanshu-receiver-offers.json"
    private static let CERT_FILE = "chuanshu-tls-rsa.crt"

    private static let TLS_LABEL = "chuanshu-tls-rsa"
    private static let TLS_TAG = Data("com.chuanshu.tls.rsa".utf8)

    private struct Served {
        let key: SecKey
        let identity: SecIdentity
        let spki: [UInt8]
    }

    private static let gate = NSRecursiveLock()
    private static var cachedIdentity: Curve25519.SigningKey?
    private static var cachedPeerId = ""
    private static var cachedServed: Served?

    private static func fail(_ why: String) -> String {
        return CsBytes.json(["error": why] as [String: Any])
    }

    // ------------------------------------------------------------------ the identity key

    /** The seed read back, or a fresh key minted and written down. The seed is the file rather than the
     *  key object because CryptoKit hands out 32 bytes and takes 32 bytes back, and a key this device
     *  cannot re-derive is a key whose pinned fingerprint dies with the process. */
    private static func signingKey() -> Curve25519.SigningKey? {
        gate.lock()
        defer { gate.unlock() }
        if let me = cachedIdentity { return me }
        if let seed = CsPaths.readBytes(SEED_FILE), seed.count == 32,
           let made = try? Curve25519.SigningKey(seed: seed) {
            cachedIdentity = made
            rememberPeerId()
            return made
        }
        let fresh = Curve25519.SigningKey.generate()
        let raw = [UInt8](fresh.publicKey.rawRepresentation)
        guard let spki = CsDer.ed25519Spki(raw: raw),
              CsPaths.writeBytes(SEED_FILE, Data(raw)),
              CsPaths.writeBytes(PUB_FILE, CsBytes.data(spki)) else { return nil }
        cachedIdentity = fresh
        mintPeerId()
        return fresh
    }

    /// 16 random bytes, hex - the same shape the other ends give their peer id.
    private static func freshPeerId() -> String {
        return CsBytes.randomHex(16)
    }

    private static func rememberPeerId() {
        if !cachedPeerId.isEmpty { return }
        let saved = (CsPaths.readText(ID_FILE) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        cachedPeerId = saved.count == 32 ? saved : freshPeerId()
        CsPaths.writeText(ID_FILE, cachedPeerId)
    }

    private static func mintPeerId() {
        cachedPeerId = freshPeerId()
        CsPaths.writeText(ID_FILE, cachedPeerId)
    }

    /** The 44 bytes a peer hashes: the 12-byte Ed25519 SPKI header and the raw key. Kept as bytes because
     *  both the fingerprint and the pair request are built from it, and the PC recomputes the same 44
     *  from the 32 it is sent (`app/net/identity.py:_spki_der`). */
    private static func spkiBytes() -> [UInt8]? {
        guard let me = signingKey() else { return nil }
        if let file = CsPaths.readBytes(PUB_FILE), file.count == 44 { return [UInt8](file) }
        guard let made = CsDer.ed25519Spki(raw: [UInt8](me.publicKey.rawRepresentation)) else { return nil }
        CsPaths.writeBytes(PUB_FILE, CsBytes.data(made))
        return made
    }

    private static func fingerprintOf(_ spki: [UInt8]) -> String {
        return CsBytes.sha256Hex(CsBytes.data(spki))
    }

    /// The name the user gave this phone, as it appears on the desktop's device card.
    public static func deviceName() -> String {
        return "iPhone · \(UIDevice.current.name)"
    }

    public static func peerId() -> String {
        if signingKey() == nil { return "" }
        gate.lock()
        defer { gate.unlock() }
        return cachedPeerId
    }

    /// {"peer_id","name","fingerprint"} - or {"error"} when this device cannot hold a key.
    public static func selfInfo() -> String {
        guard let spki = spkiBytes(), spki.count == 44 else { return fail("本机密钥不可用") }
        let id = peerId()
        if id.isEmpty { return fail("本机设备编号没能写进存储") }
        return CsBytes.json([
            "peer_id": id,
            "name": deviceName(),
            "fingerprint": fingerprintOf(spki)
        ] as [String: Any])
    }

    /** The pair request's two crypto fields: base64 of the raw 32-byte key and a signature over the
     *  bytes the caller hands in. Which message that is belongs to §3 and to cs-protocol.uts. */
    public static func signMessage(_ message: String) -> String {
        guard let me = signingKey() else { return fail("配对签名失败：本机密钥不可用") }
        guard let made = try? me.signature(for: CsBytes.utf8(message)) else { return fail("配对签名失败") }
        return CsBytes.json([
            "public_key": CsBytes.b64(me.publicKey.rawRepresentation),
            "signature": CsBytes.b64(made)
        ] as [String: Any])
    }

    public static func fingerprint() -> String {
        guard let spki = spkiBytes(), spki.count == 44 else { return "" }
        return fingerprintOf(spki)
    }

    // ------------------------------------------------------------------ trust store

    private static func readTrust() -> [[String: Any]] {
        return CsBytes.array(CsPaths.readText(TRUST_FILE) ?? "") ?? []
    }

    private static func writeTrust(_ list: [[String: Any]]) -> Bool {
        return CsPaths.writeText(TRUST_FILE, CsBytes.json(list))
    }

    /** Pin a peer by the fingerprint its TLS certificate presented, tagged with the address it was met
     *  at. peer_id is metadata only, exactly like the PC side: the digest is the anchor. */
    public static func pin(_ host: String, _ port: NSNumber, _ fingerprint: String, _ peerId: String, _ name: String) -> String {
        if fingerprint.count != 64 { return fail("指纹不是完整的 64 位十六进制，没有固定") }
        let wanted = port.intValue
        var list = readTrust()
        var replaced = false
        for index in list.indices {
            guard CsBytes.string(list[index]["fingerprint"]) == fingerprint else { continue }
            list[index]["host"] = host
            list[index]["port"] = wanted
            list[index]["peer_id"] = peerId
            list[index]["name"] = name
            replaced = true
        }
        if !replaced {
            list.append(["fingerprint": fingerprint, "host": host, "port": wanted,
                         "peer_id": peerId, "name": name])
        }
        guard writeTrust(list) else { return fail("固定指纹写不进本机存储") }
        return CsBytes.json(["count": list.count] as [String: Any])
    }

    /// What we already know about this address; non-empty means the transport must refuse a peer there
    /// presenting a different key - the hand-typed-address half of TOFU.
    public static func pinFor(_ host: String, _ port: NSNumber) -> String {
        let wanted = port.intValue
        for entry in readTrust()
        where CsBytes.string(entry["host"]) == host && CsBytes.int(entry["port"]) == wanted {
            return CsBytes.string(entry["fingerprint"])
        }
        return ""
    }

    /** Forget the pin for one address so the next connection there is a fresh first contact. */
    public static func unpin(_ host: String, _ port: NSNumber) -> String {
        let wanted = port.intValue
        let list = readTrust()
        let kept = list.filter { !(CsBytes.string($0["host"]) == host && CsBytes.int($0["port"]) == wanted) }
        let dropped = list.count - kept.count
        if dropped == 0 { return CsBytes.json(["dropped": 0] as [String: Any]) }
        guard writeTrust(kept) else { return fail("解除固定没能写进本机存储") }
        return CsBytes.json(["dropped": dropped] as [String: Any])
    }

    // ------------------------------------------------------------------ receiver memory

    public static func loadPairing() -> String {
        return CsPaths.readText(PAIRING_FILE) ?? ""
    }

    public static func savePairing(_ text: String) -> Bool {
        return CsPaths.writeText(PAIRING_FILE, text)
    }

    public static func loadTrustPeers() -> String {
        return CsPaths.readText(PEERS_FILE) ?? ""
    }

    public static func saveTrustPeers(_ text: String) -> Bool {
        return CsPaths.writeText(PEERS_FILE, text)
    }

    public static func loadOfferStates() -> String {
        return CsPaths.readText(OFFERS_FILE) ?? ""
    }

    public static func saveOfferStates(_ text: String) -> Bool {
        return CsPaths.writeText(OFFERS_FILE, text)
    }

    // ------------------------------------------------------------------ reading another key

    /** hex SHA-256 of the peer's SPKI, or '' when the request carried something that is not a key. The
     *  whole trust model hangs on this one value, so a bad key has to read as "no fingerprint" rather
     *  than as a digest of garbage. */
    public static func fpOfKeyB64(_ publicKeyB64: String) -> String {
        guard let raw = CsBytes.unb64(publicKeyB64), let spki = CsDer.ed25519Spki(raw: [UInt8](raw)) else { return "" }
        return fingerprintOf(spki)
    }

    /** Proof that the peer holds the private half of the key it just offered: verify a signature over
     *  the message the caller hands in. This is what lets a pinned peer re-pair with an empty code. */
    public static func verifyKey(_ publicKeyB64: String, _ message: String, _ signatureB64: String) -> Bool {
        guard let raw = CsBytes.unb64(publicKeyB64) else { return false }
        // Two shapes to accept: the wire carries the 32 raw bytes, and a peer that sends its SPKI whole
        // is one whose 12-byte header we can strip.
        let bytes = [UInt8](raw)
        let key: Data
        if bytes.count == 32 {
            key = CsBytes.data(bytes)
        } else if bytes.count == 44, bytes[0] == 0x30 {
            key = CsBytes.data(Array(bytes[12...43]))
        } else {
            return false
        }
        guard let pub = try? Curve25519.SigningKey(publicKey: key),
              let signature = CsBytes.unb64(signatureB64), signature.count == 64 else { return false }
        return pub.isValidSignature(signature, for: CsBytes.utf8(message))
    }

    public static func nowSeconds() -> Int64 {
        return Int64(Date().timeIntervalSince1970)
    }

    // ------------------------------------------------------------------ the served leaf

    /** The RSA-2048 key the listener signs with, kept in the keychain and never exported: the point of
     *  putting it there rather than in a file is that this device cannot hand out the private half of
     *  the number a peer expects on the socket. */
    private static func rsaKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: TLS_TAG,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        var found: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &found) == errSecSuccess, let hit = found {
            return (hit as! SecKey)
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrLabel as String: TLS_LABEL,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: TLS_TAG,
                kSecAttrLabel as String: TLS_LABEL
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let made = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { return nil }
        return made
    }

    /// The SPKI of the served key - the digest a peer expects the socket to present.
    private static func rsaSpki(_ key: SecKey) -> [UInt8]? {
        guard let pub = SecKeyCopyPublicKey(key),
              let pkcs1 = SecKeyCopyExternalRepresentation(pub, nil) else { return nil }
        return CsDer.rsaSpki(pkcs1: CsBytes.bytes(pkcs1))
    }

    /** The certificate around the key above, made once and then reused: a peer that pinned this phone
     *  yesterday has to see the same bytes tomorrow, and a stored file whose key is not the one in the
     *  keychain is silently rebuilt. */
    private static func certificate(_ key: SecKey) -> Data? {
        gate.lock()
        defer { gate.unlock() }
        guard let spki = rsaSpki(key) else { return nil }
        if let stored = CsPaths.readBytes(CERT_FILE),
           let parsed = SecCertificateCreateWithData(nil, stored as CFData),
           let publicKey = SecCertificateCopyKey(parsed),
           let theirs = SecKeyCopyExternalRepresentation(publicKey, nil),
           CsDer.rsaSpki(pkcs1: CsBytes.bytes(theirs)) == spki, !expired(parsed) {
            return stored
        }
        let id = peerId()
        if id.isEmpty { return nil }
        let made = CsDer.certificate(
            spki: spki,
            algorithm: CsDer.RSA_SHA256_ALG,
            commonName: id,
            serial: [UInt8](CsBytes.random(8)),
            notBeforeMillis: Date().timeIntervalSince1970 * 1000.0 - 86400000.0,
            // Ten years, like the other ends: a peer pins the key, so a certificate that has to be
            // re-made keeps the fingerprint it already vouched for.
            notAfterMillis: Date().timeIntervalSince1970 * 1000.0 + 315360000000.0,
            sign: { tbs in
                var error: Unmanaged<CFError>?
                guard let signed = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                                          CsBytes.data(tbs) as CFData, &error) else { return nil }
                return CsBytes.bytes(signed)
            })
        guard let der = made else { return nil }
        let out = CsBytes.data(der)
        // A leaf the framework refuses to parse is a listener that answers nothing, so say so here
        // rather than at accept() time.
        guard SecCertificateCreateWithData(nil, out as CFData) != nil else { return nil }
        CsPaths.writeBytes(CERT_FILE, out)
        addCertToKeychain(out)
        return out
    }

    private static func expired(_ cert: SecCertificate) -> Bool {
        // Deprecated in iOS 15 in favour of SecCertificateCopyValues, and still the cheapest way to ask a
        // certificate whether its own date has passed.
        guard let last = SecCertificateCopyLastTimestamp(cert) else { return false }
        return last as Date < Date()
    }

    private static func addCertToKeychain(_ der: Data) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueData as String: der
        ]
        SecItemDelete(base as CFDictionary)
        var attributes = base
        attributes[kSecAttrLabel as String] = TLS_LABEL
        SecItemAdd(attributes as CFDictionary, nil)
    }

    /** The identity a `NWListener` hands to `sec_protocol_options_set_local_identity`.
     *
     *  Two routes, because the API that builds one from a key and a certificate only arrived in iOS 14:
     *  try it, and on an older system put both in the keychain under one label and let the framework
     *  pair them by public key. */
    private static func buildIdentity() -> Served? {
        guard let key = rsaKey(), let spki = rsaSpki(key), let der = certificate(key),
              let cert = SecCertificateCreateWithData(nil, der as CFData) else { return nil }
        addCertToKeychain(der)
        if #available(iOS 14.0, *) {
            var made: SecIdentity?
            if SecIdentityCreateWithCertificate(cert, key, &made) == errSecSuccess, let identity = made {
                return Served(key: key, identity: identity, spki: spki)
            }
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: TLS_LABEL,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var found: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &found) == errSecSuccess, let hit = found else { return nil }
        // Not a force cast: a keychain that hands back something other than an identity is a route that
        // did not work, and a trap here takes the app down while the user is watching a transfer.
        guard let identity = hit as? SecIdentity else { return nil }
        return Served(key: key, identity: identity, spki: spki)
    }

    public static func tlsIdentity() -> SecIdentity? {
        gate.lock()
        defer { gate.unlock() }
        if let served = cachedServed { return served.identity }
        guard let made = buildIdentity() else { return nil }
        cachedServed = made
        return made.identity
    }

    /// Why the listener would have nothing to answer with, or '' when it has an identity. Spoken out on
    /// the receive card, because a refused port on this platform is usually a keychain question.
    public static func tlsIdentityNote() -> String {
        gate.lock()
        defer { gate.unlock() }
        if cachedServed != nil { return "" }
        guard let key = rsaKey() else { return "RSA 密钥没能进入钥匙串" }
        guard rsaSpki(key) != nil else { return "服务密钥的公钥读不出来" }
        guard certificate(key) != nil else { return "本机 TLS 证书没能生成" }
        return "本机 TLS 身份没能组成 SecIdentity"
    }

    /** What §3's fourth field carries: hex SHA-256 of the leaf this device serves, '' when the listener
     *  would have nothing to answer with. */
    public static func tlsFingerprint() -> String {
        gate.lock()
        defer { gate.unlock() }
        if let served = cachedServed { return fingerprintOf(served.spki) }
        guard let key = rsaKey(), let spki = rsaSpki(key), certificate(key) != nil else { return "" }
        return fingerprintOf(spki)
    }
}
