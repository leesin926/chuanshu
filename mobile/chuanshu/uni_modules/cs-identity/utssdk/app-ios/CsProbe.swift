import Foundation
import Network
import Security
import CryptoKit
import UIKit

/** The iPhone's own answers to the four questions the transport is built on: can this device hold an
 *  Ed25519 key, does it accept a certificate it assembled itself, can it answer a TLS connection under a
 *  keychain identity, and does its pin refuse a stranger.
 *
 *  Self-contained on purpose. `cs-transport/utssdk/app-ios` already has the same DER helpers and the same
 *  listener shape, and this file repeats them instead of calling them. One reason is mechanical - a UTS
 *  plugin's Swift does not reach into another plugin's. The reason that matters more is that a probe
 *  sharing its code with the thing under test proves nothing: if the transport's SPKI walker were wrong,
 *  a probe built on it would agree with the mistake and print success.
 *
 *  Nothing here has been compiled, let alone run, on an iPhone. Each line below is written to be read on
 *  a screen in the order a failure arrives, which is the whole reason these probes answer one question at
 *  a time instead of returning a record. */
public enum CsProbe {

    // ------------------------------------------------------------------ bytes

    private static let pairs: [String] = (0...255).map { String(format: "%02x", $0) }

    private static func hex(_ bytes: [UInt8]) -> String {
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes { out += pairs[Int(byte)] }
        return out
    }

    private static func shaHex(_ bytes: [UInt8]) -> String {
        return hex([UInt8](SHA256.hash(data: Data(bytes))))
    }

    private static func b64(_ bytes: [UInt8]) -> String {
        return Data(bytes).base64EncodedString()
    }

    /// CryptoKit hands back `ContiguousBytes`, not `Data`, and the only documented way to turn one into
    /// bytes is to copy it out while the buffer is still alive.
    private static func copyOut<S: ContiguousBytes>(_ made: S) -> [UInt8] {
        return made.withUnsafeBytes { Array($0) }
    }

    private static func randomBytes(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        let code = out.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return code == errSecSuccess ? out : [UInt8](repeating: 0x2a, count: count)
    }

    // ------------------------------------------------------------------ DER

    /** The five algorithm blocks and two SPKI heads this file needs, as their bytes rather than an
     *  encoder: 1.3.101.112 (Ed25519), rsaEncryption, sha256WithRSAEncryption, ecdsa-with-SHA256,
     *  and id-ecPublicKey + prime256v1. */
    private static let ED25519_ALG: [UInt8] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
    private static let OID_CN: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    private static let RSA_ALG: [UInt8] =
        [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
    private static let RSA_SHA256_ALG: [UInt8] =
        [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00]
    private static let ECDSA_SHA256_ALG: [UInt8] =
        [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
    private static let ED25519_SPKI_HEAD: [UInt8] =
        [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
    private static let EC_SPKI_HEAD: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]

    private static func flat(_ parts: [[UInt8]]) -> [UInt8] {
        var out: [UInt8] = []
        for part in parts { out.append(contentsOf: part) }
        return out
    }

    private static func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        let n = body.count
        if n < 0x80 {
            out.append(UInt8(n))
        } else if n < 0x100 {
            out.append(0x81)
            out.append(UInt8(n))
        } else {
            out.append(0x82)
            out.append(UInt8(n >> 8))
            out.append(UInt8(n & 0xff))
        }
        out.append(contentsOf: body)
        return out
    }

    private static func seq(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x30, flat(parts)) }
    private static func setOf(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x31, flat(parts)) }
    private static func bitString(_ payload: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + payload) }

    /// A non-negative INTEGER, minimally encoded: leading zeros off, a 0x00 added when the high bit is set.
    private static func positive(_ value: [UInt8]) -> [UInt8] {
        var body = value
        var at = 0
        while at < body.count - 1 && body[at] == 0 { at += 1 }
        body = Array(body[at...])
        if body.isEmpty { body = [0x00] }
        if body[0] & 0x80 != 0 { body = [0x00] + body }
        return tlv(0x02, body)
    }

    private static func nameOf(_ commonName: String) -> [UInt8] {
        return seq([setOf([seq([OID_CN, tlv(0x0c, [UInt8](commonName.utf8))])])])
    }

    private static func utcTime(_ epochMillis: Double) -> [UInt8] {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        let when = Date(timeIntervalSince1970: epochMillis / 1000.0)
        return tlv(0x17, [UInt8](formatter.string(from: when).utf8))
    }

    /// One element at `at`: tag, the range of its content, the range of the whole element.
    private static func read(_ data: [UInt8], _ at: Int) -> (tag: UInt8, body: Range<Int>, whole: Range<Int>)? {
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

    private static func children(_ data: [UInt8], _ body: Range<Int>) -> [(tag: UInt8, body: Range<Int>, whole: Range<Int>)] {
        var out: [(tag: UInt8, body: Range<Int>, whole: Range<Int>)] = []
        var at = body.lowerBound
        while at < body.upperBound {
            guard let one = CsProbe.read(data, at) else { break }
            out.append(one)
            at = one.whole.upperBound
        }
        return out
    }

    /** The certificate's own SubjectPublicKeyInfo, as the DER bytes inside it - unaltered, because the
     *  number a peer pinned is over the bytes that were on the wire, not over a re-encoding of them.
     *  This is the walker whose agreement with `app/net/identity.py` the dial probe exists to test. */
    private static func spki(in cert: [UInt8]) -> [UInt8]? {
        guard let outer = read(cert, 0), outer.tag == 0x30,
              let tbs = read(cert, outer.body.lowerBound), tbs.tag == 0x30 else { return nil }
        let parts = children(cert, tbs.body)
        var index = 0
        if index < parts.count && parts[index].tag == 0xA0 { index += 1 }
        index += 5
        guard index < parts.count, parts[index].tag == 0x30 else { return nil }
        return Array(cert[parts[index].whole])
    }

    /// subject == issuer == CN, the key inside is `spki`, the signature is whatever `sign` makes over the TBS.
    private static func certificate(_ spki: [UInt8], _ alg: [UInt8], _ commonName: String,
                                    _ sign: ([UInt8]) -> [UInt8]?) -> [UInt8]? {
        let now = Date().timeIntervalSince1970 * 1000.0
        let tbs = seq([
            tlv(0xa0, [0x02, 0x01, 0x02]),
            positive(randomBytes(8)),
            alg,
            nameOf(commonName),
            seq([utcTime(now - 86400000.0), utcTime(now + 315360000000.0)]),
            nameOf(commonName),
            spki
        ])
        guard let signature = sign(tbs) else { return nil }
        return seq([tbs, alg, bitString(signature)])
    }

    /** SecKey's own certificate, from a keychain key: the SPKI depends on the shape the framework
     *  exports (a PKCS#1 DER block for RSA, a bare 65-byte point for P-256), so it is picked by looking
     *  at the bytes rather than by trusting a key-type attribute. */
    private static func spkiOfSecKey(_ key: SecKey) -> [UInt8]? {
        guard let pub = SecKeyCopyPublicKey(key),
              let rep = SecKeyCopyExternalRepresentation(pub, nil) else { return nil }
        let bytes = [UInt8](rep as Data)
        if bytes.count == 65, bytes[0] == 0x04 { return EC_SPKI_HEAD + bytes }
        if bytes.first == 0x30 { return seq([RSA_ALG, bitString(bytes)]) }
        return nil
    }

    private static func secSign(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ tbs: [UInt8]) -> [UInt8]? {
        guard let made = SecKeyCreateSignature(key, algorithm, Data(tbs) as CFData, nil) else { return nil }
        return [UInt8](made as Data)
    }

    /** A keychain key that is thrown away as soon as the probe is done with it: the probe's job is to say
     *  whether the platform can make and use such a key at all, and a permanent key here would outlive
     *  the answer. */
    private static func tempKey(_ attributes: [String: Any]) -> (SecKey?, String) {
        var error: Unmanaged<CFError>?
        guard let made = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let text = error == nil ? "没有错误对象" : "\(error!.takeRetainedValue())"
            return (nil, text)
        }
        return (made, "")
    }

    private static let RSA_ATTRS: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 2048
    ]
    private static let EC_ATTRS: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256
    ]

    // ------------------------------------------------------------------ the questions

    /** The identity key: does this system hold Ed25519 at all, and does the 44 bytes it produces digest
     *  to the same number the desktop computes for the same key.
     *
     *  The last line is the one the whole trust model rests on, so the key material is printed in full:
     *  a person with a Mac and a terminal can re-hash the base64 and check it without rebuilding anything. */
    public static func identityProbe() -> String {
        var out = ""
        out = out + "ios=" + UIDevice.current.systemName + " " + UIDevice.current.systemVersion
            + " name=" + UIDevice.current.name + "\n"
        out = out + "物理内存=" + String(ProcessInfo.processInfo.physicalMemory / 1048576) + "MB\n"
        do {
            let me = Curve25519.SigningKey.generate()
            let raw = copyOut(me.publicKey.rawRepresentation)
            out = out + "keygen ok raw bytes=" + String(raw.count) + "\n"
            guard raw.count == 32 else {
                return out + "raw 公钥不是 32 字节，这一端的身份模型要重新讨论\n"
            }
            let spki = ED25519_SPKI_HEAD + raw
            out = out + "spki bytes=" + String(spki.count) + " b64=" + b64(spki) + "\n"
            out = out + "fp=" + shaHex(spki) + "\n"

            let message = [UInt8]("chuanshu-probe".utf8)
            guard let signature = try? me.signature(for: Data(message)) else {
                return out + "sign FAILED\n"
            }
            let signed = copyOut(signature)
            let pub = try? Curve25519.SigningKey(publicKey: Data(raw))
            out = out + "sig bytes=" + String(signed.count)
                + " verify=" + String(pub?.isValidSignature(signed, for: Data(message)) ?? false) + "\n"
            let stranger = Curve25519.SigningKey()
            out = out + "stranger verify="
                + String(stranger.isValidSignature(signed, for: Data(message))) + "\n"

            // The seed round trip is what lets the transport keep this key in a file: a device that cannot
            // re-derive the same public key from 32 bytes has a fingerprint that dies with the process.
            let seed = copyOut(me.representation)
            if let again = try? Curve25519.SigningKey(seed: Data(seed)) {
                out = out + "seed round trip same pub="
                    + String(copyOut(again.publicKey.rawRepresentation) == raw) + "\n"
            } else {
                out = out + "seed round trip FAILED\n"
            }

            // Why the socket answers under RSA rather than under this key, in one line each. No
            // SecKeyAlgorithm name is spelled out here on purpose: the claim the transport leans on is
            // that a *certificate* around an Ed25519 key is not accepted, and certProbe shows that with
            // bytes rather than with an API name this file might get wrong.
            let (rsaKey, rsaNote) = tempKey(RSA_ATTRS)
            out = out + "keychain rsa2048=" + String(rsaKey != nil)
                + (rsaNote.isEmpty ? "" : " " + rsaNote) + "\n"
            let (ecKey, ecNote) = tempKey(EC_ATTRS)
            out = out + "keychain p256=" + String(ecKey != nil)
                + (ecNote.isEmpty ? "" : " " + ecNote) + "\n"
            if let key = ecKey, let rep = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key), nil) {
                out = out + "keychain 256 位 EC 的公钥是 " + String([UInt8](rep as Data).count)
                    + " 字节（32 才是 Ed25519，65 是 P-256 的非压缩点）\n"
            }
        } catch {
            out = out + "stopped here: \(error)\n"
        }
        return out
    }

    /** Certificate factory: does `SecCertificateCreateWithData` take what this file hand-built, for each
     *  of the three keys, and does the walker read the same SPKI back out of the bytes that went in.
     *
     *  The Ed25519 line is the important one and is expected to be false - that is the finding the whole
     *  RSA-leaf design comes from. The RSA line has to be true or the listener has nothing to answer with. */
    public static func certProbe(_ peerId: String) -> String {
        var out = ""
        // ---- Ed25519: key in CryptoKit, certificate hand-built around it.
        let me = Curve25519.SigningKey.generate()
        let raw = copyOut(me.publicKey.rawRepresentation)
        let edSpki = ED25519_SPKI_HEAD + raw
        let edDer = certificate(edSpki, ED25519_ALG, peerId) { tbs in
            guard let made = try? me.signature(for: Data(tbs)) else { return nil }
            return copyOut(made)
        }
        if let der = edDer {
            out = out + "ed25519 der bytes=" + String(der.count) + "\n"
            out = out + "ed25519 SecCertificateCreateWithData 接受="
                + String(SecCertificateCreateWithData(nil, Data(der) as CFData) != nil) + "\n"
            out = out + "ed25519 spki 走回来一致="
                + String(spki(in: der) == edSpki) + "\n"
            out = out + "ed25519 fp=" + shaHex(spki(in: der) ?? edSpki) + "\n"
            // A check that only ever passes proves nothing, so the same signature has to be refused by a
            // key that did not make it.
            let message = [UInt8]("chuanshu-probe".utf8)
            guard let made = try? me.signature(for: Data(message)) else {
                return out + "ed25519 sign FAILED\n"
            }
            let signed = copyOut(made)
            out = out + "ed25519 自验=" + String(me.isValidSignature(signed, for: Data(message)))
                + " 陌生人验=" + String(Curve25519.SigningKey().isValidSignature(signed, for: Data(message))) + "\n"
            out = out + "ed25519 b64=" + b64(der) + "\n"
        } else {
            out = out + "ed25519 证书没能拼出来\n"
        }
        // The same signature has to be refused by a key that did not make it, and the pair has to survive
        // being read back out of the certificate the framework accepted - the Ed25519 one above is
        // expected to stop at that acceptance, which is why this half is done on the RSA key instead.
        return out + keyCase("rsa2048", RSA_ATTRS, tempKey(RSA_ATTRS), RSA_SHA256_ALG,
                             .rsaSignatureMessagePKCS1v15SHA256, peerId)
            + keyCase("p256", EC_ATTRS, tempKey(EC_ATTRS), ECDSA_SHA256_ALG,
                      .ecdsaSignatureMessageX962SHA256, peerId)
    }

    /** One keychain key, its hand-built certificate, and whether the framework will pair the two into the
     *  `SecIdentity` a listener needs. Shared by the certificate probe and the algorithm sweep, so both
     *  read the same way. */
    private static func keyCase(_ label: String, _ attributes: [String: Any], _ made: (SecKey?, String),
                                _ alg: [UInt8], _ algorithm: SecKeyAlgorithm, _ peerId: String) -> String {
        var out = ""
        guard let key = made.0 else { return out + label + " 密钥没能生成：" + made.1 + "\n" }
        guard let spki = spkiOfSecKey(key) else { return out + label + " 公钥读不出 SPKI\n" }
        let der = certificate(spki, alg, peerId) { tbs in secSign(key, algorithm, tbs) }
        guard let bytes = der else { return out + label + " 签名失败，证书没拼出来\n" }
        out = out + label + " der bytes=" + String(bytes.count) + " spki bytes=" + String(spki.count) + "\n"
        guard let cert = SecCertificateCreateWithData(nil, Data(bytes) as CFData) else {
            return out + label + " SecCertificateCreateWithData 接受=false\n"
        }
        out = out + label + " SecCertificateCreateWithData 接受=true\n"
        // The framework's own read-back has to agree with the bytes we handed it: a certificate that hands
        // back a different SubjectPublicKeyInfo is a different fingerprint, and the pin would be over the
        // wrong number. Both sides of the comparison go through the walker, so this is a statement about
        // the two documents, not about two encodings.
        let back = spki(in: [UInt8](SecCertificateCopyData(cert) as Data))
        out = out + label + " 回读一致=" + String(back == spki(in: bytes)) + " fp=" + shaHex(spki) + "\n"
        // Sign one fixed message with the key, verify it with that key's own public half and then with a
        // public half from a different key. A check that only ever passes proves nothing, and this is the
        // same pair of lines the Android and ArkTS probes print.
        let message = [UInt8]("chuanshu-probe".utf8)
        var verified = "签名失败"
        if let signed = secSign(key, algorithm, message), let theirs = SecKeyCopyPublicKey(key) {
            let own = SecKeyVerifySignature(theirs, algorithm, Data(message) as CFData, Data(signed) as CFData, nil)
            var stranger = false
            // A second key of the same kind, made the same way: the only refusal that proves the check
            // above is a check on the key rather than a check on the message.
            if let other = tempKey(attributes).0 {
                let otherPublic = SecKeyCopyPublicKey(other)
                stranger = otherPublic != nil
                    && SecKeyVerifySignature(otherPublic!, algorithm, Data(message) as CFData, Data(signed) as CFData, nil)
            }
            verified = "自验=" + String(own) + " 陌生人验=" + String(stranger)
        }
        out = out + label + " " + verified + "\n"
        if #available(iOS 14.0, *) {
            var identity: SecIdentity?
            let code = SecIdentityCreateWithCertificate(cert, key, &identity)
            out = out + label + " SecIdentityCreateWithCertificate="
                + String(code == errSecSuccess && identity != nil) + "（OSStatus " + String(Int(code)) + "）\n"
        } else {
            out = out + label + " SecIdentityCreateWithCertificate 要 iOS 14，这台系统 13.x 只能走钥匙串按标签配对\n"
        }
        return out
    }

    // ------------------------------------------------------------------ loopback TLS

    private static let serveQueue = DispatchQueue(label: "com.chuanshu.probe.serve")
    private static let dialQueue = DispatchQueue(label: "com.chuanshu.probe.dial")
    /** Long work never touches the queues that deliver events: a probe that waits for a handshake on the
     *  queue that runs the handshake waits forever. */
    private static let probeQueue = DispatchQueue(label: "com.chuanshu.probe.work")
    private static let HELLO = "GET /v1/hello HTTP/1.1\r\nHost: chuanshu\r\n\r\n"

    private final class Server {
        let lock = NSLock()
        private var lines: [String] = []
        var listener: NWListener?

        func note(_ line: String) {
            lock.lock()
            lines.append(line)
            lock.unlock()
        }

        func take() -> String {
            lock.lock()
            defer { lock.unlock() }
            return lines.joined(separator: "\n")
        }
    }

    private final class Dial {
        let lock = NSLock()
        var fp = ""
        var error = ""
        var bytes = 0
        var events = 0
        var sizes = ""
        var closed = false

        func see(_ digest: String) {
            lock.lock()
            fp = digest
            lock.unlock()
        }

        func fail(_ why: String) {
            lock.lock()
            if error.isEmpty { error = why }
            lock.unlock()
        }

        var failed: Bool {
            lock.lock()
            defer { lock.unlock() }
            return !error.isEmpty
        }
    }

    /** A TLS listener answering under `identity`. Everything it learns after the caller moves on - accept,
     *  request size, write result, the error that ended it - goes into the box, because that after-part is
     *  the half a receiving transport lives on. */
    private static func openListener(_ port: Int, _ identity: SecIdentity, _ body: String, _ box: Server) -> (Bool, String) {
        let tls = NWProtocolTLS.Options()
        guard let secID = sec_identity_create(identity) else { return (false, "sec_identity_create 返回空") }
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, secID)
        guard let number = NWEndpoint.Port(rawValue: UInt16(port)) else {
            return (false, "端口 \(port) 不在范围内")
        }
        let made: NWListener
        do {
            made = try NWListener(using: NWParameters(tls: tls), on: number)
        } catch {
            return (false, "监听没能起来：\(error)")
        }
        let ready = DispatchSemaphore(value: 0)
        var failure = ""
        made.stateUpdateHandler = { state in
            switch state {
            case .ready:
                ready.signal()
            case .failed(let error):
                failure = "监听失败：\(error)"
                box.note(failure)
                ready.signal()
            case .cancelled:
                box.note("监听已取消")
            default:
                break
            }
        }
        made.newConnectionHandler = { conn in
            box.note("accepted")
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.note("握手完成")
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, error in
                        if let why = error { box.note("读失败：\(why)") }
                        let n = data == nil ? 0 : data!.count
                        box.note("served req=" + String(n))
                        conn.send(content: Data(body.utf8), completion: .contentProcessed { sendError in
                            if let why = sendError { box.note("写失败：\(why)") }
                            box.note("sent ok " + String(body.utf8.count) + "B")
                            conn.cancel()
                        })
                    }
                case .failed(let error):
                    // The common case is our own client refusing a stranger's leaf; the server-side story
                    // of that refusal is what tells the two directions apart later.
                    box.note("连接被拒：\(error)")
                default:
                    break
                }
            }
            conn.start(queue: serveQueue)
        }
        made.start(queue: serveQueue)
        if ready.wait(timeout: .now() + 5.0) == .timedOut {
            made.cancel()
            return (false, "监听 5 秒内没有 ready" + (box.take().isEmpty ? "" : "：" + box.take()))
        }
        if !failure.isEmpty {
            made.cancel()
            return (false, failure)
        }
        box.listener = made
        return (true, "listening " + String(port))
    }

    /** One pinned request, blocking until it is answered or the deadline passes.
     *
     *  `pin` is empty for a capture round: the verify block then accepts whatever arrives and records its
     *  fingerprint, which is the only way to learn the number a peer this device has not paired with
     *  presents. That recorded value is what the next round pins, so a refusal there means the pin cannot
     *  hold a foreign certificate - not that the certificate was bad. */
    private static func dial(_ host: String, _ port: Int, _ pin: String, _ target: Int,
                             _ seconds: Double, _ box: Dial) -> String {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            var got = ""
            if let cert = SecTrustGetCertificateAtIndex(trust, 0) {
                got = CsProbe.spki(in: [UInt8](SecCertificateCopyData(cert) as Data))
                    .map { CsProbe.shaHex($0) } ?? ""
            }
            box.see(got)
            complete(pin.isEmpty || got.lowercased() == pin.lowercased())
        }, dialQueue)
        guard let number = NWEndpoint.Port(rawValue: UInt16(port)) else {
            return "端口 \(port) 不在范围内"
        }
        let conn = NWConnection(to: .hostPort(host: NWHostEndpoint(hostname: host), port: number),
                                using: NWParameters(tls: tls))
        let opened = DispatchSemaphore(value: 0)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                opened.signal()
            case .failed(let error):
                box.fail("握手没通过：\(error)")
                conn.cancel()
                opened.signal()
            case .waiting(let error):
                box.fail("连不上：\(error)")
                conn.cancel()
                opened.signal()
            case .cancelled:
                opened.signal()
            default:
                break
            }
        }
        conn.start(queue: dialQueue)
        if opened.wait(timeout: .now() + seconds) == .timedOut {
            conn.cancel()
            return "超时：\(seconds) 秒内没有完成握手"
        }
        if box.failed {
            conn.cancel()
            return box.error + "（见过 fp=" + box.fp + "）"
        }
        conn.send(content: Data(HELLO.utf8), completion: .contentProcessed { error in
            if let why = error { box.fail("写失败：\(why)") }
        })
        let stop = Date().addingTimeInterval(seconds)
        while box.bytes < target, Date() < stop, !box.failed, !box.closed {
            let step = DispatchSemaphore(value: 0)
            conn.receive(minimumIncompleteLength: 1, maximumLength: 16384) { data, _, isComplete, error in
                if let chunk = data {
                    box.lock.lock()
                    box.bytes += chunk.count
                    box.events += 1
                    if box.events <= 4 || box.events % 25 == 0 { box.sizes += " " + String(chunk.count) }
                    box.lock.unlock()
                }
                if isComplete || data == nil {
                    box.lock.lock()
                    box.closed = true
                    box.lock.unlock()
                }
                if let why = error { box.fail("读失败：\(why)") }
                step.signal()
            }
            let left = max(0.05, stop.timeIntervalSinceNow)
            if step.wait(timeout: .now() + left) == .timedOut { break }
        }
        conn.cancel()
        if box.failed { return box.error }
        return "收到 " + String(box.bytes) + "B 用 " + String(box.events) + " 包 包长:" + box.sizes
    }

    /// The leaf this probe serves: a throwaway keychain RSA-2048 key with a hand-built certificate around
    /// it. Thrown away because the probe's question is whether the pairing works, not whose key it is.
    private static func servedIdentity(_ peerId: String) -> (SecIdentity?, String, String) {
        let (key, note) = tempKey(RSA_ATTRS)
        guard let made = key else { return (nil, "", "RSA 密钥没能生成：" + note) }
        guard let spki = spkiOfSecKey(made) else { return (nil, "", "服务密钥的公钥读不出来") }
        guard let der = certificate(spki, RSA_SHA256_ALG, peerId, { tbs in
            secSign(made, .rsaSignatureMessagePKCS1v15SHA256, tbs)
        }) else { return (nil, "", "证书没能拼出来") }
        guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
            return (nil, "", "SecCertificateCreateWithData 不收这份 RSA 证书")
        }
        if #available(iOS 14.0, *) {
            var identity: SecIdentity?
            let code = SecIdentityCreateWithCertificate(cert, made, &identity)
            if code == errSecSuccess, let built = identity { return (built, shaHex(spki), "") }
            return (nil, shaHex(spki), "SecIdentityCreateWithCertificate -> OSStatus \(code)")
        }
        // iOS 13 has no factory that takes a key and a certificate, so the only route left is to put both
        // in the keychain under one label and let the framework pair them by public key. The probe reports
        // that it did not try rather than pretending the round trip worked.
        return (nil, shaHex(spki), "这台系统是 iOS 13，SecIdentity 只能从钥匙串按标签找，探针没有走那条路")
    }

    /** Probe B on the iPhone: our own certificate, our own listener, a client that trusts the fingerprint
     *  and a client that trusts a different one. Loopback keeps the run possible with no second machine.
     *
     *  The stranger round is the one that makes the other round mean something: a pin that refuses nothing
     *  is a pin that is decorative, and that is the only security claim this file has to earn. */
    public static func tlsSelfCheck(_ port: NSNumber) -> String {
        var out = ""
        let wanted = Int(truncating: port)
        let (identity, fp, note) = servedIdentity("ios-probe-01")
        out = out + "served fp=" + fp + (note.isEmpty ? "" : " 说明：" + note) + "\n"
        guard let built = identity else { return out + "没有身份可用，监听这一步谈不到\n" }
        let box = Server()
        let (ok, line) = openListener(wanted, built, "{\"peer_id\":\"" + String(fp.prefix(8)) + "\",\"hello\":\"chuanshu\"}", box)
        out = out + line + "\n"
        guard ok else { return out }
        let pinned = Dial()
        out = out + "pinned: " + dial("127.0.0.1", wanted, fp, 1, 8.0, pinned)
            + " fp 相同=" + String(pinned.fp == fp) + "\n"
        let stranger = Dial()
        let wrong = shaHex([UInt8]("不是这台设备的密钥".utf8))
        let said = dial("127.0.0.1", wanted, wrong, 1, 8.0, stranger)
        out = out + "stranger REJECTED=" + String(!stranger.fp.isEmpty && stranger.fp != wrong) + " " + said + "\n"
        box.listener?.cancel()
        return out + "--- server ---\n" + box.take() + "\n"
    }

    /** One case of the sweep: build an identity for this key algorithm, then serve and pin one loopback
     *  round with it. Ed25519 is expected to stop at the certificate; RSA and P-256 are the two shapes the
     *  listener could actually answer under, and which of them works is the open question. */
    public static func tlsAlgProbe(_ port: NSNumber) -> String {
        var out = ""
        let base = Int(truncating: port)
        // ---- Ed25519: no keychain key exists, so the certificate is the only thing that can be tried.
        let me = Curve25519.SigningKey.generate()
        let edSpki = ED25519_SPKI_HEAD + copyOut(me.publicKey.rawRepresentation)
        let edDer = certificate(edSpki, ED25519_ALG, "ios-probe-01") { tbs in
            guard let made = try? me.signature(for: Data(tbs)) else { return nil }
            return copyOut(made)
        }
        if let der = edDer {
            out = out + "ed25519: der=" + String(der.count) + "B 证书被接受="
                + String(SecCertificateCreateWithData(nil, Data(der) as CFData) != nil)
                + "（没有钥匙串私钥，谈不到 SecIdentity 与监听）\n"
        } else {
            out = out + "ed25519: 证书没能拼出来\n"
        }
        // ---- RSA-2048 and P-256, each with its own listener and its own pinned round.
        out = out + sweepCase("rsa2048", base, RSA_ATTRS, RSA_SHA256_ALG, .rsaSignatureMessagePKCS1v15SHA256)
        out = out + sweepCase("p256", base + 1, EC_ATTRS, ECDSA_SHA256_ALG, .ecdsaSignatureMessageX962SHA256)
        return out
    }

    private static func sweepCase(_ label: String, _ port: Int, _ attributes: [String: Any],
                                  _ alg: [UInt8], _ algorithm: SecKeyAlgorithm) -> String {
        var out = ""
        let t0 = Date()
        let (key, note) = tempKey(attributes)
        out = out + label + " 密钥 " + String(Int(Date().timeIntervalSince(t0) * 1000.0)) + "ms"
            + (note.isEmpty ? "" : "：" + note) + "\n"
        guard let made = key else { return out + label + " 到这一步停住了\n" }
        guard let spki = spkiOfSecKey(made) else { return out + label + " 公钥读不出 SPKI\n" }
        guard let der = certificate(spki, alg, label + "-probe") { tbs in secSign(made, algorithm, tbs) } else {
            return out + label + " 签名失败，证书没拼出来\n"
        }
        guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else {
            return out + label + " 证书被拒绝，监听这一步谈不到\n"
        }
        // An availability condition only belongs on an `if`: `guard #available` is not the form the
        // compiler accepts, and a probe that will not build answers nothing.
        if #available(iOS 14.0, *) {
            var identity: SecIdentity?
            let code = SecIdentityCreateWithCertificate(cert, made, &identity)
            guard code == errSecSuccess, let built = identity else {
                return out + label + " SecIdentityCreateWithCertificate -> OSStatus \(code)\n"
            }
            let fp = shaHex(spki)
            let box = Server()
            let (ok, line) = openListener(port, built, "{\"hello\":\"chuanshu\",\"from\":\"" + label + "\"}", box)
            out = out + label + " " + line + " fp=" + String(fp.prefix(16)) + "\n"
            if ok {
                let client = Dial()
                out = out + label + " 回路固定客户端：" + dial("127.0.0.1", port, fp, 1, 8.0, client) + "\n"
                box.listener?.cancel()
            }
            return out
        }
        return out + label + " iOS 13 没有 SecIdentityCreateWithCertificate，这一格没有测到\n"
    }

    // ------------------------------------------------------------------ against the PC's stack

    /** The PC's two scratch listeners: 43730 answers with an Ed25519 leaf, 43731 with an RSA one.
     *
     *  Every roundtrip elsewhere in this file is our own code talking to our own code. These four are the
     *  only ones that can show that the SPKI digest this walker produces is the same number the desktop
     *  computes over the same key - which is the agreement a pairing is made of. */
    public static func pcDial(_ host: String, _ edPort: Int, _ rsaPort: Int, _ report: (String) -> Void) {
        var out = ""
        let say: (String) -> Void = { line in
            out = out + line + "\n"
            report(out)
        }
        let ed = Dial()
        say("ed25519 捕获 " + host + ":" + String(edPort) + " → " + dial(host, edPort, "", 1, 8.0, ed)
            + " fp=" + ed.fp)
        let pinnedEd = Dial()
        say("ed25519 固定 → " + dial(host, edPort, ed.fp, 1, 8.0, pinnedEd)
            + (ed.fp.isEmpty ? "（上一轮没捕到证书，这一轮等于没固定）" : " fp 相同=" + String(pinnedEd.fp == ed.fp)))
        let rsa = Dial()
        say("rsa2048 捕获 " + host + ":" + String(rsaPort) + " → " + dial(host, rsaPort, "", 1, 8.0, rsa)
            + " fp=" + rsa.fp)
        let pinnedRsa = Dial()
        say("rsa2048 固定 → " + dial(host, rsaPort, rsa.fp, 1, 8.0, pinnedRsa)
            + " fp 相同=" + String(pinnedRsa.fp == rsa.fp))
    }

    private static var held: Server?

    /** Opens a TLS listener and leaves it open so the PC is the one that connects - the direction the
     *  receiving half lives in, and one no loopback test can prove, because both ends would be our own code.
     *  Reach it from the desktop over the LAN address this phone reports on the receive card. */
    public static func holdListener(_ port: NSNumber, _ done: @escaping (String) -> Void) {
        let box = Server()
        let (identity, fp, note) = servedIdentity("ios-listener")
        guard let built = identity else {
            done("没有身份可用：" + note + "\n")
            return
        }
        let wanted = Int(truncating: port)
        let (ok, line) = openListener(wanted, built, "{\"hello\":\"chuanshu\",\"from\":\"ios\"}", box)
        if ok { held = box }
        done(line + "\nfp=" + fp + "\n")
    }

    /// The listener keeps reporting after the page stopped being handed text, so a PC connection that
    /// arrives later has to be read on demand rather than awaited by the button that started it.
    public static func holdListenerLog() -> String {
        guard let box = held else { return "还没有起过监听\n" }
        let text = box.take()
        return text.isEmpty ? "还没有东西连进来\n" : text + "\n"
    }

    /** Read a bulk stream from a server that is not our own code and report the sizes the platform's TLS
     *  client actually handed the app, per event.
     *
     *  The receiving half of this transport was broken on the *server* connection of the other phone for
     *  a while - events arriving in sizes the sender never wrote. Whether an iPhone's client can carry a
     *  stream is the question that decides whether that was a record-sizing problem or a direction
     *  problem, and no loopback test inside our own transport can answer it. */
    public static func bulkRead(_ host: String, _ port: NSNumber, _ total: NSNumber,
                                _ done: @escaping (String) -> Void) {
        let box = Dial()
        let wanted = Int(truncating: port)
        let line = dial(host, wanted, "", Int(truncating: total), 12.0, box)
        done("从 " + host + ":" + String(wanted) + " 读 " + String(Int(truncating: total)) + "B：" + line + "\n")
    }

    // ------------------------------------------------------------------ dispatch

    /** Every entry point below goes through here, and every callback is delivered on the main queue because
     *  that is where a `ref` is allowed to change.
     *
     *  There is no catch in this shape on purpose: a Swift trap is not a thrown error and cannot be turned
     *  into text, it takes the process with it. That is why each probe prints the line it just finished
     *  before starting the next one - the last line on the screen is the crash report. */
    private static func report(_ body: @escaping () -> String, _ done: @escaping (String) -> Void) {
        probeQueue.async {
            let text = body()
            DispatchQueue.main.async {
                done(text)
            }
        }
    }

    public static func identityProbeAsync(_ done: @escaping (String) -> Void) {
        report({ CsProbe.identityProbe() }, done)
    }

    public static func certProbeAsync(_ done: @escaping (String) -> Void) {
        report({ CsProbe.certProbe("ios-probe-01") }, done)
    }

    public static func tlsSelfCheckAsync(_ port: NSNumber, _ done: @escaping (String) -> Void) {
        report({ CsProbe.tlsSelfCheck(port) }, done)
    }

    public static func tlsAlgProbeAsync(_ port: NSNumber, _ done: @escaping (String) -> Void) {
        report({ CsProbe.tlsAlgProbe(port) }, done)
    }

    public static func pcDialAsync(_ host: String, _ done: @escaping (String) -> Void) {
        probeQueue.async {
            CsProbe.pcDial(host, 43730, 43731) { text in
                DispatchQueue.main.async {
                    done(text)
                }
            }
        }
    }

    public static func holdListenerAsync(_ port: NSNumber, _ done: @escaping (String) -> Void) {
        probeQueue.async {
            CsProbe.holdListener(port) { text in
                DispatchQueue.main.async {
                    done(text)
                }
            }
        }
    }

    public static func bulkReadAsync(_ host: String, _ port: NSNumber, _ total: NSNumber,
                                     _ done: @escaping (String) -> Void) {
        probeQueue.async {
            CsProbe.bulkRead(host, port, total) { text in
                DispatchQueue.main.async {
                    done(text)
                }
            }
        }
    }
}
