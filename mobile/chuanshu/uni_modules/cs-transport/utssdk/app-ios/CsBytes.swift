import Foundation
import CryptoKit
import Security

/** Byte-level helpers and the app's own directories, shared by every Swift file in this plugin.
 *
 *  Nothing here crosses back into UTS: the boundary is JSON text and `Data`, which is why the hex and
 *  DER formats live once, in this file, instead of being re-derived by each caller. A peer pins the
 *  SHA-256 of a SubjectPublicKeyInfo, so the encoder and the walker below have to agree with
 *  `app/net/identity.py` byte for byte - the same rule the Kotlin and ArkTS halves follow. */
public enum CsBytes {

    private static let pairs: [String] = (0...255).map { String(format: "%02x", $0) }

    private static let values: [Character: Int] = {
        var out: [Character: Int] = [:]
        for (index, ch) in Array("0123456789abcdef").enumerated() { out[ch] = index }
        for (index, ch) in Array("ABCDEF").enumerated() { out[ch] = 10 + index }
        return out
    }()

    static func hex(_ data: Data) -> String {
        var out = ""
        out.reserveCapacity(data.count * 2)
        for byte in data { out += pairs[Int(byte)] }
        return out
    }

    static func hex(_ bytes: [UInt8]) -> String {
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes { out += pairs[Int(byte)] }
        return out
    }

    /// nil rather than a truncated decode: a half-byte at the end means the text is not a digest.
    static func unhex(_ text: String) -> [UInt8]? {
        var out: [UInt8] = []
        var high = -1
        for ch in text {
            guard let value = values[ch] else { return nil }
            if high < 0 {
                high = value
            } else {
                out.append(UInt8(high * 16 + value))
                high = -1
            }
        }
        return high < 0 ? out : nil
    }

    static func utf8(_ text: String) -> Data {
        return text.data(using: .utf8) ?? Data()
    }

    static func bytes(_ data: Data) -> [UInt8] {
        return [UInt8](data)
    }

    static func data(_ bytes: [UInt8]) -> Data {
        return Data(bytes)
    }

    static func sha256(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }

    static func sha256(_ bytes: [UInt8]) -> Data {
        return Data(SHA256.hash(data: bytes))
    }

    static func sha256Hex(_ data: Data) -> String {
        return hex(sha256(data))
    }

    static func b64(_ data: Data) -> String {
        return data.base64EncodedString()
    }

    /** A pair request's key and signature arrive as base64 the sender may have wrapped at 76 columns
     *  (Python's `base64.encodebytes` does), so the whitespace has to come off before decoding. */
    static func unb64(_ text: String) -> Data? {
        let cleaned = text.components(separatedBy: CharacterSet.whitespacesAndNewlines).joined()
        if cleaned.isEmpty { return nil }
        return Data(base64Encoded: cleaned)
    }

    /// 8 or 16 bytes off the system CSPRNG, hex - the same shape `secrets.token_hex()` gives the PC.
    static func randomHex(_ count: Int) -> String {
        return hex(random(count))
    }

    static func random(_ count: Int) -> Data {
        if count <= 0 { return Data() }
        var out = Data(count: count)
        let made = out.withUnsafeMutableBytes { pointer -> Int32 in
            guard let raw = pointer.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, count, raw)
        }
        return made == errSecSuccess ? out : Data()
    }

    /// JSON text for dictionaries and arrays, `{}` if the value is something JSON cannot hold.
    static func json(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(value) else { return "{}" }
        guard let raw = try? JSONSerialization.data(withJSONObject: value, options: []) else { return "{}" }
        return String(data: raw, encoding: .utf8) ?? "{}"
    }

    static func object(_ text: String) -> [String: Any]? {
        let raw = CsBytes.utf8(text)
        guard !raw.isEmpty else { return nil }
        return (try? JSONSerialization.jsonObject(with: raw, options: [])) as? [String: Any]
    }

    static func array(_ text: String) -> [[String: Any]]? {
        let raw = CsBytes.utf8(text)
        guard !raw.isEmpty else { return nil }
        return (try? JSONSerialization.jsonObject(with: raw, options: [])) as? [[String: Any]]
    }

    static func string(_ value: Any?) -> String {
        if let text = value as? String { return text }
        if let number = value as? NSNumber { return number.stringValue }
        return ""
    }

    static func int(_ value: Any?) -> Int {
        if let number = value as? NSNumber { return number.intValue }
        if let text = value as? String { return Int(text) ?? 0 }
        return 0
    }
}

/** The one directory tree this app owns.
 *
 *  Application Support rather than Documents: none of this is user data a person would look for in the
 *  Files app, and Documents is backed up and surfaced there by default. The identity key, the pins and
 *  the received files all sit under it, which is the same trade the desktop made with its own data
 *  directory - uninstall takes them with it. */
public enum CsPaths {

    private static let fm = FileManager.default

    static func identityDir() -> URL? {
        return ensured("Chuanshu")
    }

    /** Where a receiving device puts the bytes: the same leaf name the desktop and the phone halves
     *  use, so a runbook written for one reads the same on this one. */
    static func receiveDir() -> URL? {
        return ensured("Chuanshu/chuanshu-receive")
    }

    private static func ensured(_ relative: String) -> URL? {
        guard let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let dir = base.appendingPathComponent(relative, isDirectory: true)
        if !fm.fileExists(atPath: dir.path) {
            do { try fm.createDirectory(at: dir, withIntermediateDirectories: true) } catch { return nil }
        }
        return dir
    }

    static func readText(_ name: String) -> String? {
        guard let url = identityDir()?.appendingPathComponent(name) else { return nil }
        guard let raw = try? Data(contentsOf: url) else { return nil }
        return String(data: raw, encoding: .utf8)
    }

    static func readBytes(_ name: String) -> Data? {
        guard let url = identityDir()?.appendingPathComponent(name) else { return nil }
        return try? Data(contentsOf: url)
    }

    static func writeText(_ name: String, _ text: String) -> Bool {
        return writeBytes(name, CsBytes.utf8(text))
    }

    static func writeBytes(_ name: String, _ data: Data) -> Bool {
        guard let url = identityDir()?.appendingPathComponent(name) else { return false }
        do { try data.write(to: url, options: .atomic) } catch { return false }
        return true
    }
}

/** Just enough DER to build a self-signed certificate and to read a SubjectPublicKeyInfo back out of
 *  one that someone else built.
 *
 *  Hand-built because there is no certificate issuer in the system frameworks this end can call: the
 *  alternative is a third-party library, and a dependency this machine cannot fetch or verify is worse
 *  than forty lines of ASN.1. `spki(in:)` is the read half of the same contract - it returns the
 *  element's bytes *unaltered*, because the digest a peer pinned is over exactly the DER that was on
 *  the wire, not over a re-encoding of it. */
public enum CsDer {

    static let OID_ED25519: [UInt8] = [0x06, 0x03, 0x2b, 0x65, 0x70]
    static let OID_CN: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    static let OID_RSA: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
    static let OID_RSA_SHA256: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
    static let NULL: [UInt8] = [0x05, 0x00]

    static let ED25519_ALG: [UInt8] = seq([OID_ED25519])
    static let RSA_ALG: [UInt8] = seq([OID_RSA, NULL])
    static let RSA_SHA256_ALG: [UInt8] = seq([OID_RSA_SHA256, NULL])

    /** The 12 bytes in front of every Ed25519 SubjectPublicKeyInfo: SEQUENCE{ SEQUENCE{ OID 1.3.101.112 },
     *  BIT STRING(32) }. A pair request carries only the 32 raw bytes after this, and rebuilding the head
     *  is what makes both ends hash the same 44. */
    static let ED25519_SPKI_HEAD: [UInt8] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]

    static func flat(_ parts: [[UInt8]]) -> [UInt8] {
        var out: [UInt8] = []
        for part in parts { out.append(contentsOf: part) }
        return out
    }

    static func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        let n = body.count
        if n < 0x80 {
            out.append(UInt8(n))
        } else if n < 0x100 {
            out.append(0x81)
            out.append(UInt8(n))
        } else if n < 0x10000 {
            out.append(0x82)
            out.append(UInt8(n >> 8))
            out.append(UInt8(n & 0xff))
        } else {
            return []
        }
        out.append(contentsOf: body)
        return out
    }

    static func seq(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x30, flat(parts)) }
    static func setOf(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x31, flat(parts)) }

    /// A non-negative INTEGER, minimally encoded: no leading zeros, and a 0x00 when the high bit is set.
    static func positive(_ value: [UInt8]) -> [UInt8] {
        var body = value
        var at = 0
        while at < body.count - 1 && body[at] == 0 { at += 1 }
        body = Array(body[at...])
        if body.isEmpty { body = [0x00] }
        if body[0] & 0x80 != 0 { body = [0x00] + body }
        return tlv(0x02, body)
    }

    static func utf8String(_ text: String) -> [UInt8] {
        return tlv(0x0c, [UInt8](CsBytes.utf8(text)))
    }

    /// UTCTime - `yyMMddHHmmssZ`, the form RFC 5280 requires for dates before 2050, which is the whole
    /// lifetime of the certificates this end issues (ten years from now).
    static func utcTime(_ epochMillis: Double) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        let when = Date(timeIntervalSince1970: epochMillis / 1000.0)
        return tlv(0x17, [UInt8](CsBytes.utf8(formatter.string(from: when))))
    }

    static func bitString(_ payload: [UInt8]) -> [UInt8] {
        return tlv(0x03, [0x00] + payload)
    }

    static func name(_ commonName: String) -> [UInt8] {
        return seq([setOf([seq([OID_CN, utf8String(commonName)])])])
    }

    // ------------------------------------------------------------------ reading someone else's

    /// One element at `at`: its tag, the range of its content, and the range of the whole element.
    static func read(_ data: [UInt8], _ at: Int) -> (tag: UInt8, body: Range<Int>, whole: Range<Int>)? {
        guard at + 1 < data.count else { return nil }
        let tag = data[at]
        let first = Int(data[at + 1])
        var start = at + 2
        var length = 0
        if first & 0x80 == 0 {
            length = first
        } else {
            let count = first & 0x7f
            if count == 0 || count > 3 { return nil }
            for _ in 0..<count {
                if start >= data.count { return nil }
                length = length * 256 + Int(data[start])
                start += 1
            }
        }
        let end = start + length
        if length < 0 || end > data.count { return nil }
        return (tag, start..<end, at..<end)
    }

    static func children(_ data: [UInt8], _ body: Range<Int>) -> [(tag: UInt8, body: Range<Int>, whole: Range<Int>)] {
        var out: [(tag: UInt8, body: Range<Int>, whole: Range<Int>)] = []
        var at = body.lowerBound
        while at < body.upperBound {
            guard let one = read(data, at) else { break }
            out.append(one)
            at = one.whole.upperBound
        }
        return out
    }

    /** The certificate's own SubjectPublicKeyInfo, as the DER bytes that appear inside it, or nil when
     *  the document is not a certificate this walker can follow. */
    static func spki(in cert: [UInt8]) -> [UInt8]? {
        guard let outer = read(cert, 0), outer.tag == 0x30,
              let tbs = read(cert, outer.body.lowerBound), tbs.tag == 0x30 else { return nil }
        let parts = children(cert, tbs.body)
        var index = 0
        if index < parts.count && parts[index].tag == 0xA0 { index += 1 }
        index += 5
        guard index < parts.count, parts[index].tag == 0x30 else { return nil }
        return Array(cert[parts[index].whole])
    }

    /// RSAPublicKey DER (what `SecKeyCopyExternalRepresentation` hands back for an RSA key) wrapped in
    /// the SPKI the fingerprint is computed over.
    static func rsaSpki(pkcs1: [UInt8]) -> [UInt8] {
        return seq([RSA_ALG, bitString(pkcs1)])
    }

    static func ed25519Spki(raw: [UInt8]) -> [UInt8]? {
        if raw.count == 44 { return raw }
        if raw.count != 32 { return nil }
        return ED25519_SPKI_HEAD + raw
    }

    // ------------------------------------------------------------------ building our own

    /** A self-signed certificate: subject == issuer == CN=peer id, the key inside it is `spki`, and the
     *  signature is whatever `sign` makes over the TBSCertificate.
     *
     *  The serial is the caller's random bytes, and the validity is a day in the past to ten years
     *  forward - a peer pins the *public key*, so a certificate that has to be re-made keeps the
     *  fingerprint it already vouched for. */
    static func certificate(spki: [UInt8], algorithm: [UInt8], commonName: String, serial: [UInt8],
                            notBeforeMillis: Double, notAfterMillis: Double,
                            sign: ([UInt8]) -> [UInt8]?) -> [UInt8]? {
        let tbs = seq([
            tlv(0xa0, [0x02, 0x01, 0x02]),
            positive(serial),
            algorithm,
            name(commonName),
            seq([utcTime(notBeforeMillis), utcTime(notAfterMillis)]),
            name(commonName),
            spki
        ])
        guard let signature = sign(tbs) else { return nil }
        return seq([tbs, algorithm, bitString(signature)])
    }
}
