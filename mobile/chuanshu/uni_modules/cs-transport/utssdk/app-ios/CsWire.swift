import Foundation
import Network
import Security

/** Moving bytes to a peer that must be the one we chose: one TLS connection per request, pinned by the
 *  SHA-256 of the leaf's SubjectPublicKeyInfo, and file reads for the paths the iOS picker hands back.
 *
 *  Network.framework rather than URLSession, because this contract has no host name to validate: a peer's
 *  certificate is signed with `CN=<peer_id>`, so TLS would fail URI matching for every real peer and the
 *  identity has to come from the pinned digest instead. URLSession cannot express that - it can challenge
 *  a trust it has already built, but it can never serve, and this file pair has to do both. The framework's
 *  verify block is the one place where a leaf can be read and judged before any endpoint runs.
 *
 *  Blocking is deliberate. `../cs-client.uts` is the state machine and it calls a request as a function
 *  that answers, so each of these waits on a semaphore from the worker thread the UTS half handed it -
 *  never from the queue the connection itself is delivering events on, which would deadlock. */
public enum CsWire {

    private static let CONNECT_TIMEOUT_S = 8.0

    /** What one connection accumulates: the answer, plus the leaf the handshake actually saw. */
    private final class Session {
        let lock = NSLock()
        var head = -1          // index just past \r\n\r\n, -1 while the headers are incomplete
        var declared = -1
        var status = 0
        var bodyText = ""
        var seen = ""
        var error = ""
        var detail = ""
        var bytes = Data()
        var closed = false

        var failed: Bool {
            lock.lock()
            defer { lock.unlock() }
            return !error.isEmpty
        }
    }

    private static func fail(_ session: Session, _ code: String, _ why: String) {
        session.lock.lock()
        if session.error.isEmpty {
            session.error = code
            session.detail = why
        }
        session.lock.unlock()
    }

    private static func errorJson(_ code: String, _ detail: String) -> String {
        return CsBytes.json(["error": code, "detail": detail] as [String: Any])
    }

    /// Waits, but never past the deadline the request was given.
    private static func waitUntil(_ step: DispatchSemaphore, _ deadline: Date) -> Bool {
        let left = deadline.timeIntervalSinceNow
        if left <= 0 { return false }
        return step.wait(timeout: .now() + left) != .timedOut
    }

    // ------------------------------------------------------------------ pinning

    /** The leaf's own SPKI digest, walked out of the certificate rather than re-encoded from anything:
     *  the number a peer pinned is over the DER that was on the wire. */
    private static func leafFingerprint(_ trust: SecTrust) -> String {
        guard let cert = SecTrustGetCertificateAtIndex(trust, 0) else { return "" }
        let der = CsBytes.bytes(SecCertificateCopyData(cert) as Data)
        guard let spki = CsDer.spki(in: der) else { return "" }
        return CsBytes.sha256Hex(CsBytes.data(spki))
    }

    /** spec §2's weighing, on the socket. A pin arrives in two shapes: the whole digest a pin store or a
     *  QR's `f=` carries, and the shorter prefix a LAN announcement has room for, which has to be the
     *  beginning of what the peer presents. The same rule the other ends state
     *  (`cs-protocol.uts::pinAccepts`, `CsWire.kt::pinAccepts`, and Python's `read_fingerprint`).
     *
     *  iOS is out of scope, so this half is read rather than run: it changes because the shared store now
     *  hands a 16-character prefix to `request`, and a whole-digest comparison here would fail every
     *  request of such a session. */
    private static func matchesPin(_ expected: String, _ got: String) -> Bool {
        if expected.count == 64 {
            return got.compare(expected, options: .caseInsensitive) == .orderedSame
        }
        return got.range(of: expected, options: .caseInsensitive)?.lowerBound == got.startIndex
    }

    /** An empty expectation means first contact: the QR's fingerprint has not been seen yet, the pair code
     *  is what carries the trust there, and §3 keeps this end from sending a file before the peer's
     *  fingerprint has been written to the trust store. */
    private static func pin(_ options: NWProtocolTLS.Options, _ expected: String, _ session: Session, _ queue: DispatchQueue) {
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { _, sec_trust, complete in
            let trust = sec_trust_copy_ref(sec_trust).takeRetainedValue()
            let got = leafFingerprint(trust)
            session.lock.lock()
            session.seen = got
            session.lock.unlock()
            if got.isEmpty {
                fail(session, "IO", "对端没有交证书")
                complete(false)
                return
            }
            if expected.isEmpty || matchesPin(expected, got) {
                complete(true)
                return
            }
            fail(session, "TLS_PIN_MISMATCH", "期望 \(expected)，收到 \(got)")
            complete(false)
        }, queue)
    }

    private static func reasonOf(_ raw: Error?, _ session: Session, _ host: String) {
        guard let error = raw else { return }
        guard let nw = error as? NWError else {
            fail(session, "IO", "\(error)")
            return
        }
        switch nw {
        case .dns(let code):
            fail(session, "HOST_UNKNOWN", host + "（dns \(code)）")
        case .tls(let code):
            // Our own verify block already named the reason when it refused the leaf; a bare TLS code with
            // no pin in front of it is the peer refusing something, which is an IO story.
            if session.seen.isEmpty { fail(session, "IO", "握手没通过（\(code)）") }
        case .posix(let code):
            switch code {
            case .ECONNREFUSED: fail(session, "CONN_REFUSED", host + " 拒了这条连接")
            case .ECONNRESET: fail(session, "CONN_RESET", "对端把连接拔了")
            case .ETIMEDOUT: fail(session, "TIMEOUT", host)
            default: fail(session, "IO", "\(code)")
            }
        default:
            if !session.failed { fail(session, "IO", "\(error)") }
        }
    }

    // ------------------------------------------------------------------ HTTP/1.1
    //
    // The four framing helpers below are shared with CsServe.swift: both halves of this plugin read the
    // same request shape, and a second copy is a second way for the two to disagree.

    /// Where `\r\n\r\n` ends, as the index just past it, or -1 while the headers are still coming.
    public static func headerEnd(_ data: Data) -> Int {
        let bytes = [UInt8](data)
        if bytes.count < 4 { return -1 }
        var at = 0
        while at + 4 <= bytes.count {
            if bytes[at] == 0x0d, bytes[at + 1] == 0x0a, bytes[at + 2] == 0x0d, bytes[at + 3] == 0x0a {
                return at + 4
            }
            at += 1
        }
        return -1
    }

    public static func headerLines(_ head: Data) -> [String] {
        return String(decoding: head, as: UTF8.self).components(separatedBy: "\r\n")
    }

    public static func statusCode(_ head: Data) -> Int {
        guard let line = headerLines(head).first else { return 0 }
        let parts = line.split(separator: " ")
        guard parts.count >= 2, let code = Int(parts[1]) else { return 0 }
        return code
    }

    public static func contentLength(_ head: Data) -> Int {
        for line in headerLines(head).dropFirst() {
            let lower = line.lowercased()
            if lower.hasPrefix("content-length:") {
                return Int(String(lower.dropFirst(15)).trimmingCharacters(in: .whitespaces)) ?? -1
            }
        }
        return -1
    }

    /// One header from a request or response block, lower-cased name to trimmed value.
    public static func header(_ head: Data, _ name: String) -> String {
        for line in headerLines(head).dropFirst() {
            let lower = line.lowercased()
            guard lower.hasPrefix(name) else { continue }
            return String(line.dropFirst(name.count)).trimmingCharacters(in: .whitespaces)
        }
        return ""
    }

    /** One request, one connection, and always a JSON string out of it: either
     *  {"status":<code>,"body":"...","fp":"..."} or {"error":<transport code>,"detail":"..."}.
     *
     *  `Connection: close` is deliberate. Keeping a socket alive across the user's accept-or-decline window
     *  would mean a minutes-long read timeout on every chunk request instead of only on the offer - and on
     *  this platform the offer is not parked on a connection at all, it is answered and then polled. */
    public static func http(
        _ method: String,
        _ host: String,
        _ port: NSNumber,
        _ path: String,
        _ json: String,
        _ token: String,
        _ pinHex: String,
        _ body: Data?,
        _ sha: String,
        _ escape: String,
        _ timeoutMs: NSNumber
    ) -> String {
        let session = Session()
        let queue = DispatchQueue(label: "com.chuanshu.wire")
        let tls = NWProtocolTLS.Options()
        pin(tls, pinHex, session, queue)
        let wanted = UInt16(truncating: port)
        guard let number = NWEndpoint.Port(rawValue: wanted) else {
            return errorJson("HOST_UNKNOWN", "端口 \(wanted) 不在范围内")
        }
        let conn = NWConnection(to: .hostPort(host: NWHostEndpoint(hostname: host), port: number),
                                using: NWParameters(tls: tls))
        let opened = DispatchSemaphore(value: 0)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                opened.signal()
            case .failed(let error):
                reasonOf(error, session, host)
                conn.cancel()
                opened.signal()
            case .waiting(let error):
                // A peer that is not reachable right now is a refused connection, not a prompt: the user
                // pressed 连接 and deserves an answer rather than a spinner until the timeout.
                reasonOf(error, session, host)
                conn.cancel()
                opened.signal()
            case .cancelled:
                opened.signal()
            default:
                break
            }
        }
        conn.start(queue: queue)
        if !waitUntil(opened, Date().addingTimeInterval(CONNECT_TIMEOUT_S)) {
            conn.cancel()
            return errorJson("TIMEOUT", host + " 没在 8 秒内接上")
        }
        if session.failed {
            conn.cancel()
            return finish(session)
        }

        let jsonBytes = CsBytes.bytes(json)
        let payload = body ?? Data()
        let length = payload.isEmpty ? jsonBytes.count : payload.count
        var head = CsBytes.data(CsBytes.bytes("\(method) \(path) HTTP/1.1\r\n"
            + "Host: \(host):\(wanted)\r\n"
            + "User-Agent: chuanshu-ios\r\n"
            + "Accept: application/json\r\n"
            + "Connection: close\r\n"))
        if !token.isEmpty { head.append(contentsOf: CsBytes.bytes("X-Chuanshu-Auth: \(token)\r\n")) }
        if !sha.isEmpty { head.append(contentsOf: CsBytes.bytes("X-Sha256: \(sha)\r\n")) }
        // Declared by the sender, obeyed by the receiver only when present: a peer whose TLS server hands
        // its scripts the body up to the first 0x00 cannot be given raw bytes at all (spec §4).
        if !escape.isEmpty { head.append(contentsOf: CsBytes.bytes("X-Chunk-Escape: \(escape)\r\n")) }
        head.append(contentsOf: CsBytes.bytes("Content-Length: \(length)\r\n\r\n"))

        let deadline = Date().addingTimeInterval(Double(Int(truncating: timeoutMs)) / 1000.0)
        if !send(conn, head, queue, deadline, session) { conn.cancel(); return finish(session) }
        let out = payload.isEmpty ? jsonBytes : payload
        if !out.isEmpty, !send(conn, out, queue, deadline, session) {
            conn.cancel()
            return finish(session)
        }
        readUntilWhole(conn, deadline, session)
        conn.cancel()
        return finish(session)
    }

    private static func send(_ conn: NWConnection, _ data: Data, _ queue: DispatchQueue,
                             _ deadline: Date, _ session: Session) -> Bool {
        let step = DispatchSemaphore(value: 0)
        conn.send(content: data, completion: .contentProcessed { error in
            reasonOf(error, session, "")
            step.signal()
        })
        if !waitUntil(step, deadline) {
            fail(session, "TIMEOUT", "对端没有把这一段收下")
            return false
        }
        return !session.failed
    }

    /// One receive, signalled either way.
    private static func receiveOnce(_ conn: NWConnection, _ step: DispatchSemaphore, _ session: Session) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
            reasonOf(error, session, "")
            if let chunk = data { session.bytes.append(chunk) }
            if isComplete || data == nil { session.closed = true }
            step.signal()
        }
    }

    /** Read until the status line, the headers and the whole body are in. A declared `Content-Length` is
     *  the contract; an early close with nothing declared is what EOF means here. Both are answered rather
     *  than assumed, because a peer that hangs up mid-body must read as PROTOCOL, not as an empty file.
     *
     *  The buffer is only ever inspected after the receive that filled it has signalled, so the read of
     *  `bytes`/`closed` here needs no lock - a check before the wait would be a second thread in the same
     *  array. */
    private static func readUntilWhole(_ conn: NWConnection,
                                       _ deadline: Date, _ session: Session) {
        let step = DispatchSemaphore(value: 0)
        receiveOnce(conn, step, session)
        while true {
            if !waitUntil(step, deadline) {
                fail(session, "TIMEOUT", "等这一句答话等超时了")
                return
            }
            if session.failed { return }
            if session.head < 0 {
                let end = headerEnd(session.bytes)
                if end > 0 {
                    session.head = end
                    session.declared = contentLength(session.bytes.subdata(in: 0..<end))
                    session.status = statusCode(session.bytes.subdata(in: 0..<end))
                }
            }
            if session.head >= 0 {
                let have = session.bytes.count - session.head
                if session.declared >= 0, have >= session.declared {
                    takeBody(session)
                    return
                }
                if session.declared < 0, session.closed {
                    takeBody(session)
                    return
                }
                if session.closed {
                    fail(session, "PROTOCOL", "对端在正文中途挂了")
                    return
                }
            } else if session.closed {
                fail(session, "PROTOCOL", "对端在头之前就挂了")
                return
            }
            receiveOnce(conn, step, session)
        }
    }

    private static func takeBody(_ session: Session) {
        session.lock.lock()
        if session.status == 0 {
            session.lock.unlock()
            fail(session, "PROTOCOL", "对端没答话")
            return
        }
        let slice = session.bytes.subdata(in: session.head..<session.bytes.count)
        session.bodyText = String(decoding: slice, as: UTF8.self)
        session.lock.unlock()
    }

    private static func finish(_ session: Session) -> String {
        if session.error != "" {
            return errorJson(session.error, session.detail)
        }
        if session.status == 0 {
            return errorJson("PROTOCOL", session.detail == "" ? "对端没答话" : session.detail)
        }
        return CsBytes.json([
            "status": session.status,
            "body": session.bodyText,
            // The digest the handshake actually saw, not what the peer's JSON claims about itself, so the
            // caller pins the key rather than a number the peer typed.
            "fp": session.seen
        ] as [String: Any])
    }

    // ------------------------------------------------------------------ bytes and ids

    public static func digest(_ data: Data?) -> String {
        return CsBytes.sha256Hex(data ?? Data())
    }

    /// 8 random bytes in hex - the same shape app/net uses (`token_hex(8)`), because the PC treats these as
    /// opaque and keys its resume map on them.
    public static func newId() -> String {
        return CsBytes.randomHex(8)
    }

    // ------------------------------------------------------------------ outgoing files

    private static var lastRead = ""

    public static func readError() -> String {
        return lastRead
    }

    /** The picker's path, whatever shape it came in.
     *
     *  `uni.chooseFile` on iOS hands back a real path inside this app's container, and a document picked
     *  from the Files app has been copied there by the time the callback runs. A `file://` spelling of the
     *  same thing is what a paste produces, so both are accepted and nothing else is attempted: there is no
     *  Android-style content:// provider on this platform. */
    private static func asPath(_ text: String) -> String {
        if text.hasPrefix("file://") {
            return URL(string: text)?.path ?? ""
        }
        return text
    }

    /// Bytes at an offset, shorter only at the end of the file. Opened fresh every time, so a file that
    /// changed after 清单 was computed cannot be served from a stale descriptor.
    public static func readSlice(_ path: String, _ offset: NSNumber, _ length: NSNumber) -> Data? {
        let want = Int(truncating: length)
        let from = Int64(truncating: offset)
        if want <= 0 { return Data() }
        lastRead = ""
        let file = asPath(path)
        guard let handle = FileHandle(forReadingAtPath: file) else {
            lastRead = "打不开这个文件：\(file)"
            return nil
        }
        defer { handle.closeFile() }
        handle.seek(toFileOffset: UInt64(from < 0 ? 0 : from))
        let got = handle.readData(ofLength: want)
        if got.isEmpty {
            lastRead = "读到 0 字节，文件可能已被清理"
            return nil
        }
        return got
    }

    /** The offer row for one picked file: its length, the SHA-256 of the whole thing, a modification time,
     *  and a MIME type - or an error to show in its place. */
    public static func prepare(_ path: String) -> String {
        let file = asPath(path)
        let name = (file as NSString).lastPathComponent
        guard let handle = FileHandle(forReadingAtPath: file) else {
            return CsBytes.json(["error": "打不开这个文件：\(name)"] as [String: Any])
        }
        defer { handle.closeFile() }
        var hasher = SHA256Stream()
        var size = 0
        while true {
            let block = handle.readData(ofLength: 256 * 1024)
            if block.isEmpty { break }
            hasher.update(block)
            size += block.count
        }
        let attrs = try? FileManager.default.attributesOfItem(atPath: file)
        let modified = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? Date().timeIntervalSince1970
        return CsBytes.json([
            "size": size,
            "sha256": CsBytes.hex(hasher.final()),
            "mtime": Int64(modified),
            "type": mimeOf(name),
            "name": name
        ] as [String: Any])
    }

    /** A short table rather than `UTType.mime`: that API is iOS 14+, its answer for a file the picker
     *  copied is often `public.data` with no MIME at all, and the value only ever reaches the other end as
     *  a label. Anything unlisted travels as a file, which is what it is. */
    private static func mimeOf(_ name: String) -> String {
        let dot = (name as NSString).pathExtension.lowercased()
        let table: [String: String] = [
            "txt": "text/plain", "md": "text/plain", "log": "text/plain", "csv": "text/csv",
            "json": "application/json", "xml": "application/xml", "yaml": "text/yaml",
            "html": "text/html", "htm": "text/html", "css": "text/css", "js": "text/javascript",
            "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif",
            "webp": "image/webp", "heic": "image/heic", "bmp": "image/bmp", "svg": "image/svg+xml",
            "mp4": "video/mp4", "mov": "video/quicktime", "m4a": "audio/mp4", "mp3": "audio/mpeg",
            "wav": "audio/wav", "aac": "audio/aac", "pdf": "application/pdf",
            "zip": "application/zip", "gz": "application/gzip", "tar": "application/x-tar",
            "7z": "application/x-7z-compressed", "doc": "application/msword",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls": "application/vnd.ms-excel",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "ppt": "application/vnd.ms-powerpoint",
            "apk": "application/vnd.android.package-archive"
        ]
        return table[dot] ?? "application/octet-stream"
    }

    // ------------------------------------------------------------------ same network

    /** Four bytes in memory, read in network order: the same order an address is spoken. */
    private static func quad(_ addr: in_addr) -> [UInt8] {
        return withUnsafeBytes(of: addr) { raw in [UInt8](raw.prefix(4)) }
    }

    private static func dotted(_ addr: in_addr) -> String {
        let b = quad(addr)
        return "\(b[0]).\(b[1]).\(b[2]).\(b[3])"
    }

    private static func prefixOf(_ mask: in_addr) -> Int {
        let b = quad(mask)
        var value: UInt32 = 0
        for byte in b { value = (value << 8) | UInt32(byte) }
        return value.nonzeroBitCount
    }

    /** This device's own IPv4 addresses with their prefix lengths, so the page can say whether the peer it
     *  is about to connect to is on the network the phone is actually joined to.
     *
     *  Read from the interfaces rather than guessed: the prefix is what makes a 10/8 site answer honestly
     *  instead of assuming a /24 that the IT department never set. `en0` is Wi-Fi and `pdp_ip0` cellular,
     *  and both are reported - the check is about the network, not about the radio. */
    public static func lan() -> String {
        var list: [[String: Any]] = []
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else {
            return CsBytes.json(["error": "网卡信息读不出来"] as [String: Any])
        }
        defer { freeifaddrs(first) }
        var cursor = first
        while let entry = cursor {
            let flags = Int32(entry.pointee.ifa_flags)
            if let raw = entry.pointee.ifa_addr,
               Int32(raw.pointee.sa_family) == AF_INET,
               flags & IFF_UP == IFF_UP,
               flags & IFF_LOOPBACK == 0,
               let mask = entry.pointee.ifa_netmask {
                let sin = raw.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                let msin = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                list.append([
                    "addr": dotted(sin.sin_addr),
                    "prefix": prefixOf(msin.sin_addr),
                    "iface": String(cString: entry.pointee.ifa_name)
                ])
            }
            cursor = entry.pointee.ifa_next
        }
        return CsBytes.json(["addrs": list] as [String: Any])
    }
}
