import Foundation
import Network
import Security

/** The iPhone as the peer that gets connected *to*: one TLS listener on the transport port, one request
 *  per connection, and every request handed to the same state machine the browser and the Android half
 *  drive (`../cs-receive.uts`). The listener adds nothing to the protocol; it only moves bytes.
 *
 *  Three things here are deliberate:
 *
 *  - No parked connections, and no blocking on the delivery queue. `POST /v1/offer` is answered straight
 *    away with "nobody has decided yet" and the sender asks again on a fresh connection - what Harmony's
 *    receiver had to be changed to once a real phone was involved (task #59), because a platform that ends
 *    a TLS session while a person is still looking at the screen takes the answer with it. The decision
 *    therefore lives in the inbox and the sender's poll is what delivers it.
 *  - `X-Chunk-Escape` is decoded here, before the state machine sees the body. The desktop escapes every
 *    PUT body that contains a zero byte and declares it in the header (spec §4), so a receiver that
 *    ignores the header stores escaped bytes under a digest of the plain ones.
 *  - One lock around the state machine. The web host has JavaScript's single thread for free; here the
 *    connection callbacks arrive on this file's queue while the page reads the same inbox from the main
 *    thread, so `gate()` is how UTS says "this is the critical section". */
public enum CsServe {

    /** A chunk is 4 MiB; twice that is a sender that has lost the plot, and a head over 8 KiB is not this
     *  protocol. Both are answered by hanging up rather than by buffering an attacker's memory claim. */
    private static let MAX_BODY = 8 * 1024 * 1024
    private static let MAX_HEAD = 8192
    private static let READ_DEADLINE_S = 120.0

    private static let gateLock = NSRecursiveLock()
    private static let notesLock = NSLock()
    private static var notes: [String] = []
    private static var blobs: [Int: Data] = [:]
    private static var counter = 1
    private static var handler: ((String) -> String)?
    private static var listener: NWListener?
    private static var workQueue = DispatchQueue(label: "com.chuanshu.serve")
    private static var liveConnections: [NWConnection] = []
    private static var running = false
    private static var boundPort = 0

    private static func note(_ text: String) {
        notesLock.lock()
        notes.append(text)
        while notes.count > 24 { notes.removeFirst() }
        notesLock.unlock()
    }

    public static func noteLog() -> String {
        notesLock.lock()
        defer { notesLock.unlock() }
        return CsBytes.json(notes)
    }

    public static func isRunning() -> Bool {
        return running
    }

    public static func port() -> Int {
        return boundPort
    }

    public static func nowSeconds() -> Int64 {
        return CsIdentity.nowSeconds()
    }

    /** Run the shared state machine's access under the listener's lock. UTS calls this with the body that
     *  touches the inbox, so a chunk landing on this queue cannot interleave with the user tapping 接受.
     *  Recursive, because the request handler that this file invokes re-enters it for its own critical
     *  section. */
    public static func gate(_ body: () -> String) -> String {
        gateLock.lock()
        defer { gateLock.unlock() }
        return body()
    }

    /** The binary body of the request at `index`, consumed once. A 4 MiB chunk crosses as `Data` instead of
     *  as base64 inside the request JSON, because the sender's digest is over these exact bytes and a text
     *  round trip would only add a way to get them wrong. */
    public static func takeBlob(_ index: NSNumber) -> Data? {
        gateLock.lock()
        defer { gateLock.unlock() }
        return blobs.removeValue(forKey: index.intValue)
    }

    // ------------------------------------------------------------------ one connection

    /** Best effort, and only ever used for the pair-code lockout and the notes: the peer's address as the
     *  framework spells it, with whatever quoting that spelling carries taken off. */
    private static func peerAddress(_ conn: NWConnection) -> String {
        guard case .hostPort(let host, _) = conn.endpoint else { return "" }
        let text = "\(host)"
        if text.count >= 2, text.hasPrefix("\""), text.hasSuffix("\"") {
            return String(text.dropFirst().dropLast())
        }
        return text
    }

    private static func reasonOf(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 400: return "Bad Request"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 422: return "Unprocessable Entity"
        case 429: return "Too Many Requests"
        case 507: return "Insufficient Storage"
        default: return "Status"
        }
    }

    private static func forget(_ conn: NWConnection) {
        gateLock.lock()
        liveConnections.removeAll { $0 === conn }
        gateLock.unlock()
    }

    private static func writeBack(_ conn: NWConnection, _ status: Int, _ body: String) {
        let raw = CsBytes.bytes(body)
        var head = CsBytes.data(CsBytes.bytes("HTTP/1.1 \(status) \(reasonOf(status))\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: \(raw.count)\r\n"
            + "Connection: close\r\n\r\n"))
        head.append(contentsOf: CsBytes.data(raw))
        conn.send(content: head, completion: .contentProcessed { _ in
            forget(conn)
            conn.cancel()
        })
    }

    /// Nothing waits here: the answer is already in the inbox, and a sender that has to ask again is the
    /// design rather than a fallback.
    private static func hangUp(_ conn: NWConnection, _ why: String) {
        note(why)
        forget(conn)
        conn.cancel()
    }

    /** `0x1B` `0x1B` means a literal escape and `0x1B` `B` means a zero byte; a trailing or unknown escape
     *  is left as the byte it is, exactly as `app/net/spec.py:unescape_chunk` reads it. Only ever called on
     *  a body whose header declared this encoding. */
    private static func unescape(_ bytes: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var at = 0
        while at < bytes.count {
            guard bytes[at] == 0x1b else {
                out.append(bytes[at])
                at += 1
                continue
            }
            guard at + 1 < bytes.count else {
                out.append(0x1b)
                at += 1
                continue
            }
            if bytes[at + 1] == 0x1b {
                out.append(0x1b)
            } else if bytes[at + 1] == 0x42 {
                out.append(0)
            } else {
                out.append(0x1b)
                out.append(bytes[at + 1])
            }
            at += 2
        }
        return out
    }

    private static func nextIndex() -> Int {
        gateLock.lock()
        defer { gateLock.unlock() }
        counter += 1
        return counter
    }

    private static func deliver(_ conn: NWConnection, _ all: Data, _ end: Int) {
        let head = all.subdata(in: 0..<end)
        let lines = CsWire.headerLines(head)
        let line0 = lines.first ?? ""
        let bits = line0.components(separatedBy: " ")
        guard bits.count >= 2 else {
            hangUp(conn, "请求行读不出方法：\(line0)")
            return
        }
        let method = bits[0]
        let path = bits[1]
        var body = all.subdata(in: end..<all.count)
        let escape = CsWire.header(head, "x-chunk-escape:")
        if !escape.isEmpty, method == "PUT", !body.isEmpty {
            // Both digests, so a rejected chunk says which half of this end is wrong: if the wire digest
            // matches what the sender hashed over its escaped bytes the bytes came through and the decode is
            // at fault; if it does not, the platform handed this connection something else.
            let plain = CsBytes.data(unescape(CsBytes.bytes(body)))
            note("反解 \(escape)：收到 \(body.count) 解出 \(plain.count) 线上=\(CsBytes.digest(body).prefix(12)) 解后=\(CsBytes.digest(plain).prefix(12))")
            body = plain
        }
        let index = nextIndex()
        let binary = method == "PUT" && !body.isEmpty
        if binary {
            gateLock.lock()
            blobs[index] = body
            gateLock.unlock()
        }
        let request = CsBytes.json([
            "index": index,
            "method": method,
            "path": path,
            "token": CsWire.header(head, "x-chuanshu-auth:"),
            "sha": CsWire.header(head, "x-sha256:"),
            "client": peerAddress(conn),
            "json": binary ? "" : String(decoding: body, as: UTF8.self),
            "blob": binary ? body.count : 0
        ] as [String: Any])
        guard let answer = handler?(request) else {
            note("页面还没有登记接收处理器")
            blobs.removeValue(forKey: index)
            writeBack(conn, 400, "{\"code\":\"UNSUPPORTED_PROTOCOL\",\"detail\":{\"reason\":\"no handler\"}}")
            return
        }
        blobs.removeValue(forKey: index)
        guard let reply = CsBytes.object(answer) else {
            note("状态机的应答不是 JSON：\(answer)")
            forget(conn)
            conn.cancel()
            return
        }
        let status = CsBytes.int(reply["status"])
        writeBack(conn, status == 0 ? 400 : status, CsBytes.string(reply["body"]))
    }

    /** Read the request, asynchronously. `minimumIncompleteLength: 1` means the completion can answer with a
     *  partial record, so this only stops when the head is whole and the declared body has landed - and a
     *  body that never finishes is cut off by the deadline the caller set, not by a timeout on the socket. */
    private static func readRequest(_ conn: NWConnection, _ bag: NSMutableData, _ deadline: Date) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
            if let e = error {
                hangUp(conn, "这条连接断开：\(e)")
                return
            }
            if bag.length > MAX_BODY + MAX_HEAD {
                hangUp(conn, "请求体超出上限，已经挂断")
                return
            }
            if let chunk = data { bag.append(chunk) }
            let all = bag as Data
            let end = CsWire.headerEnd(all)
            if end > 0 {
                let declared = CsWire.contentLength(all.subdata(in: 0..<end))
                if declared >= 0 {
                    if all.count >= end + declared {
                        deliver(conn, all, end)
                        return
                    }
                } else if isComplete {
                    deliver(conn, all, end)
                    return
                }
            } else if isComplete {
                hangUp(conn, "对端在头之前就挂了")
                return
            }
            if Date() > deadline {
                hangUp(conn, "这条连接迟迟没有把请求写完")
                return
            }
            readRequest(conn, bag, deadline)
        }
    }

    /** Whether this connection ever reached `.ready`. Read and written only on `workQueue`, so the flag
     *  needs no lock of its own - it exists because a connection that never becomes ready also never gets
     *  the read deadline that `readRequest` would have set for it. */
    private final class Inflight {
        var ready = false
    }

    private static func serveOne(_ conn: NWConnection) {
        let deadline = Date().addingTimeInterval(READ_DEADLINE_S)
        let inflight = Inflight()
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                inflight.ready = true
                readRequest(conn, NSMutableData(), deadline)
            case .failed(let e):
                hangUp(conn, "这条连接没建立：\(e)")
            case .waiting(let e):
                hangUp(conn, "这条连接在等待：\(e)")
            case .cancelled:
                forget(conn)
            default:
                break
            }
        }
        conn.start(queue: workQueue)
        // The handshake itself has no deadline anywhere else, so this one check is for a connection that
        // is started but never becomes ready; once it is ready, `readRequest` owns the clock.
        workQueue.asyncAfter(deadline: .now() + READ_DEADLINE_S + 1) {
            if !inflight.ready { hangUp(conn, "这条连接没有送来一个完整请求") }
        }
    }

    // ------------------------------------------------------------------ the listener

    /// TLS needs our key and a certificate whose public key is the one both ends have been hashing.
    private static func parameters() -> (NWParameters, String) {
        let tls = NWProtocolTLS.Options()
        guard let identity = CsIdentity.tlsIdentity(),
              let secID = sec_identity_create(identity) else {
            return (NWParameters(tls: tls), CsIdentity.tlsIdentityNote())
        }
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, secID)
        return (NWParameters(tls: tls), "")
    }

    /** `fn` is stored, not just called - the listener answers a request minutes after the page pressed
     *  the button - so it has to be `@escaping`. Swift treats the assignment below as an error otherwise,
     *  which is the kind of thing worth writing down next to the one line that proves it. */
    public static func start(_ port: NSNumber, _ fn: @escaping (String) -> String) -> String {
        gateLock.lock()
        defer { gateLock.unlock() }
        handler = fn
        if running {
            return CsBytes.json(["listening": boundPort] as [String: Any])
        }
        let (params, why) = parameters()
        if why != "" {
            note("监听没能起来：\(why)")
            return CsBytes.json(["error": why] as [String: Any])
        }
        let wanted = UInt16(truncating: port)
        guard let number = NWEndpoint.Port(rawValue: wanted) else {
            return CsBytes.json(["error": "端口 \(wanted) 不在范围内"] as [String: Any])
        }
        let made: NWListener
        do {
            made = try NWListener(using: params, on: number)
        } catch {
            note("监听没能起来：\(error)")
            return CsBytes.json(["error": "\(error)"] as [String: Any])
        }
        let ready = DispatchSemaphore(value: 0)
        var failure = ""
        made.stateUpdateHandler = { state in
            switch state {
            case .ready:
                boundPort = Int(made.port?.rawValue ?? wanted)
                running = true
                ready.signal()
            case .failed(let e):
                failure = "\(e)"
                running = false
                ready.signal()
            case .cancelled:
                running = false
                ready.signal()
            default:
                break
            }
        }
        made.newConnectionHandler = { incoming in
            liveConnections.append(incoming)
            serveOne(incoming)
        }
        listener = made
        // `start` is called from the UTS io dispatcher, never from this queue, so waiting for the listener
        // to report ready cannot starve the callbacks that would signal it.
        made.start(queue: workQueue)
        if ready.wait(timeout: .now() + 5) == .timedOut {
            made.cancel()
            listener = nil
            note("监听没能起来：5 秒内没有 ready")
            return CsBytes.json(["error": "监听没有就绪"] as [String: Any])
        }
        if failure != "" {
            listener = nil
            note("监听没能起来：\(failure)")
            return CsBytes.json(["error": failure] as [String: Any])
        }
        note("开始监听 \(boundPort)")
        return CsBytes.json(["listening": boundPort] as [String: Any])
    }

    /** Closing the listener wakes nothing that was parked, because nothing parks; the open connections are
     *  hung up on so a sender is never left holding a socket after this end decided to stop. */
    public static func stop() -> String {
        gateLock.lock()
        running = false
        let old = listener
        listener = nil
        let open = liveConnections
        liveConnections.removeAll()
        let pending = blobs.count
        blobs.removeAll()
        gateLock.unlock()
        old?.cancel()
        for conn in open {
            conn.cancel()
        }
        note("已经不再监听")
        return CsBytes.json(["stopped": true, "parked": pending] as [String: Any])
    }
}
