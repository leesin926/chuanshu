import Foundation

/** The iPhone's half of discovery: two sockets and a name, nothing else.
 *
 *  Everything that *decides* - merging by fingerprint prefix, expiring a silent peer, refusing a version
 *  this build cannot speak, filtering out our own announcement - lives in utssdk/cs-discovery.uts and runs
 *  identically in the browser, on Android and on Harmony. This file moves bytes and reports what it had to
 *  do about them. It never parses an announcement and never holds a roster, because a phone that grew its
 *  own merge rules would be a phone the desktop cannot be found by.
 *
 *  Two channels, both required by spec §2, with different failure shapes here:
 *
 *  - The datagram path is Network.framework's `NWConnection` for sending, but nothing in that framework
 *    can *receive* a broadcast addressed to 255.255.255.255, and `NWListener` binds unicast. So this half
 *    is the BSD socket: `SO_BROADCAST` before the first send, `SO_REUSEADDR` so a restart can retake 43721
 *    while the previous listener is still on the way out, and `SO_RCVTIMEO` because a blocking `recvfrom`
 *    with no deadline is a thread `stop()` can never get back. iOS has no Android-style multicast lock -
 *    keeping the Wi-Fi radio awake for a listener is the system's job, not ours.
 *  - DNS-SD is Bonjour: one `NetService` published and one `NetServiceBrowser` searching. Both need a run
 *    loop to deliver their delegate callbacks, so - exactly like Android's `NsdManager` - publish and
 *    browse are started on the main thread and their answers arrive there. A search started from this
 *    file's queue would look like it worked and never call anybody back.
 *
 *  The TXT record is where spec §2's `fp` lives, and without it a resolved service is a name and an
 *  address with nothing to pin. A goodbye names the service, not the machine, so which name resolved to
 *  which prefix is remembered here the way the desktop's `_mdns_names` does it.
 *
 *  The escape route is the pairing QR and the typed address, and both work when neither channel does -
 *  which is why a dead channel is a sentence in `status()`, never a silent empty list. */
public enum CsDiscovery {

    private static let MAX_PACKET = 4096
    private static let LIMITED_BROADCAST = "255.255.255.255"

    private static let recvQueue = DispatchQueue(label: "com.chuanshu.discovery.recv")
    private static let timerQueue = DispatchQueue(label: "com.chuanshu.discovery.timer")

    private static let notesLock = NSLock()
    private static let warnLock = NSLock()
    private static let mapLock = NSLock()
    private static var notes: [String] = []
    private static var warnings: [String] = []
    private static var prefixesByService: [String: String] = [:]

    private static var running = false
    private static var announceSource: DispatchSourceTimer?

    /** The bound socket. `fdLock` guards it because the receive loop owns closing it while the announce
     *  timer reads it, and a file descriptor closed under a `sendto` that is already in flight is not a
     *  harmless race - the number can be handed to another thread's socket. */
    private static let fdLock = NSLock()
    private static var sendFd: Int32 = -1
    private static var boundUdpPort: Int32 = 0

    private static var browser: NetServiceBrowser?
    private static var published: NetService?
    private static var delegate: CsDiscoveryDelegate?

    private static var udpState = "stopped"
    private static var udpDetail = ""
    private static var mdnsState = "stopped"
    private static var mdnsDetail = ""
    private static var bytesIn = 0
    private static var packetsSent = 0
    private static var servicesFound = 0
    private static var servicesLost = 0

    private static func note(_ text: String) {
        notesLock.lock()
        notes.append(text)
        while notes.count > 24 { notes.removeFirst() }
        notesLock.unlock()
    }

    /** Once per sentence, and capped: a VPN interface that refuses every broadcast would otherwise push
     *  the real failure off the end of the log every three seconds. */
    private static func warn(_ text: String) {
        warnLock.lock()
        let fresh = !warnings.contains(text) && warnings.count < 6
        if fresh { warnings.append(text) }
        warnLock.unlock()
        if fresh { note("警告：" + text) }
    }

    private static func fd() -> Int32 {
        fdLock.lock()
        defer { fdLock.unlock() }
        return sendFd
    }

    // ------------------------------------------------------------------ lifecycle

    /** @param port the discovery datagram port (contract `ports.discovery_udp`; unlike 43720 it may not fall back)
     *  @param intervalS how often to re-announce (contract `discovery.announce_interval_s`)
     *  @param serviceType DNS-SD type, e.g. `_chuanshu._tcp.`
     *  @param provider builds one announcement: `{"announce":text,"service":name,"port":tls,"txt":[…]}`
     *  @param inbound every packet and every DNS-SD answer, as `{"via":…}` JSON
     *
     *  Both closures are called from threads this enum owns and from the main run loop, so neither may
     *  touch a UI; the roster they reach is guarded by `CsServe.gate()` on the UTS side. */
    public static func start(_ port: NSNumber, _ intervalS: NSNumber, _ serviceType: String,
                             _ provider: @escaping () -> String,
                             _ inbound: @escaping (String) -> Void) -> String {
        if running {
            return status()
        }
        running = true
        bytesIn = 0
        packetsSent = 0
        servicesFound = 0
        servicesLost = 0
        mapLock.lock()
        prefixesByService.removeAll()
        mapLock.unlock()
        warnLock.lock()
        warnings.removeAll()
        warnLock.unlock()
        startUdp(port.int32Value, intervalS.doubleValue, provider, inbound)
        startBonjour(serviceType, provider, inbound)
        note("发现已启动（广播端口 \(port.int32Value)，服务类型 \(serviceType)）")
        return status()
    }

    /** Close both paths. `stop()` does not wait on the receive loop: that loop is blocked in `recvfrom`
     *  and will notice `running` within one `SO_RCVTIMEO`, then close the descriptor itself. Waiting here
     *  would put the page's thread behind a socket it cannot interrupt. */
    public static func stop() -> String {
        if !running {
            return status()
        }
        running = false
        announceSource?.cancel()
        announceSource = nil
        DispatchQueue.main.async {
            teardownBonjour()
        }
        udpState = "stopped"
        udpDetail = ""
        mdnsState = "stopped"
        mdnsDetail = ""
        note("发现已停止")
        return status()
    }

    public static func isRunning() -> Bool {
        return running
    }

    /** Channels, counters and the last lines of what happened - the panel shows `detail` when a path is
     *  down, because "发现不到设备" is not actionable and "广播端口 43721 没能绑上：…，可以用配对二维码" is. */
    public static func status() -> String {
        warnLock.lock()
        let warned = warnings
        warnLock.unlock()
        notesLock.lock()
        let lines = notes
        notesLock.unlock()
        return CsBytes.json([
            "udp": ["state": udpState, "detail": udpDetail],
            "mdns": ["state": mdnsState, "detail": mdnsDetail],
            "warnings": warned,
            "counts": ["bytes_in": bytesIn, "sent": packetsSent,
                       "found": servicesFound, "lost": servicesLost],
            "notes": lines
        ] as [String: Any])
    }

    // ------------------------------------------------------------------- UDP path

    private static func setOption(_ sk: Int32, _ level: Int32, _ name: Int32, _ value: Int32) -> Bool {
        var held = value
        return setsockopt(sk, level, name, &held, socklen_t(MemoryLayout<Int32>.size)) == 0
    }

    private static func unbound(_ port: Int32) -> Int32 {
        let sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        if sk < 0 {
            note("广播套接字创建失败：\(lastError())")
            return -1
        }
        // Options before bind, as on Android: SO_BROADCAST has to be on the socket before it can answer a
        // 255.255.255.255 send, and SO_REUSEADDR is what lets a restart retake the port.
        if !setOption(sk, SOL_SOCKET, SO_REUSEADDR, 1) || !setOption(sk, SOL_SOCKET, SO_BROADCAST, 1) {
            note("广播套接字选项设不上：\(lastError())")
            close(sk)
            return -1
        }
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        if setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) != 0 {
            note("广播收包超时设不上：\(lastError())")
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        // Every interface, the way the contract's listener wants it: the socket receives the directed
        // broadcasts of the subnets this phone is on as well as the limited one.
        addr.sin_addr = in_addr(s_addr: UInt32(INADDR_ANY))
        let bound = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { name in
                bind(sk, name, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bound != 0 {
            note("广播端口 \(port) 没能绑上：\(lastError())")
            close(sk)
            return -1
        }
        return sk
    }

    private static func lastError() -> String {
        return String(cString: strerror(errno))
    }

    private static func startUdp(_ port: Int32, _ intervalS: Double,
                                 _ provider: @escaping () -> String,
                                 _ inbound: @escaping (String) -> Void) {
        let sk = unbound(port)
        if sk < 0 {
            udpState = "unavailable"
            udpDetail = "广播端口 \(port) 没能绑上：\(lastError())"
            return
        }
        fdLock.lock()
        sendFd = sk
        fdLock.unlock()
        boundUdpPort = port
        udpState = "ok"
        udpDetail = ""

        // The loop owns the descriptor: it exits when `running` goes false and closes it then, so nothing
        // else can close it under an in-flight send.
        recvQueue.async {
            var bag = [UInt8](repeating: 0, count: MAX_PACKET)
            while running {
                var from = sockaddr_in()
                var length = socklen_t(MemoryLayout<sockaddr_in>.size)
                let read = withUnsafeMutablePointer(to: &from) { pointer -> ssize_t in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { name in
                        bag.withUnsafeMutableBufferPointer { bytes in
                            recvfrom(sk, bytes.baseAddress, MAX_PACKET, 0, name, &length)
                        }
                    }
                }
                if read < 0 {
                    if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                        continue
                    }
                    if running {
                        note("广播收包中断：\(lastError())")
                        udpState = "unavailable"
                        udpDetail = lastError()
                    }
                    break
                }
                // An IPv6 announcement would need a scope id to be dialled back and the contract's hello
                // path has none, so anything not IPv4 is ignored rather than answered wrongly. `read == 0`
                // is a closed sender: no bytes, no candidate.
                if read == 0 || Int(from.sin_len) != MemoryLayout<sockaddr_in>.size {
                    continue
                }
                let host = addressText(from.sin_addr)
                if host == "" {
                    continue
                }
                bytesIn += Int(read)
                let text = String(bytes: bag[0..<Int(read)], encoding: .utf8) ?? ""
                if text == "" {
                    continue
                }
                deliver(inbound, CsBytes.json([
                    "via": "udp", "host": host, "text": text
                ] as [String: Any]))
            }
            fdLock.lock()
            if sendFd == sk { sendFd = -1 }
            fdLock.unlock()
            close(sk)
        }

        // One packet up front, then the contract's interval: a phone that just joined the network should
        // appear on the desktop within a second, not after the first full interval.
        let source = DispatchSource.makeTimerSource(queue: timerQueue)
        let seconds = max(intervalS, 1.0)
        source.schedule(deadline: .now(), repeating: seconds)
        source.setEventHandler {
            announceOnce(provider)
        }
        announceSource = source
        source.resume()
    }

    private static func addressText(_ addr: in_addr) -> String {
        var copy = addr
        var buffer = [Int8](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let made = inet_ntop(AF_INET, &copy, &buffer, socklen_t(INET_ADDRSTRLEN))
        guard let text = made else { return "" }
        return String(cString: text)
    }

    /** Four bytes in network order, from the same dotted spelling the page shows. */
    private static func addressNumber(_ text: String) -> UInt32? {
        var addr = in_addr()
        guard inet_pton(AF_INET, text, &addr) == 1 else { return nil }
        return addr.s_addr
    }

    private static func announceOnce(_ provider: () -> String) {
        let sk = fd()
        if sk < 0 {
            return
        }
        // A provider that cannot build an announcement is a phone with no identity, and there is nothing
        // to send; the same empty answer the other platforms get, reported by the roster's own note.
        guard let made = CsBytes.object(provider()),
              let body = (made["announce"] as? String)?.utf8 else {
            return
        }
        let bytes = Array(body)
        if bytes.isEmpty {
            return
        }
        for target in broadcastTargets() {
            guard let number = addressNumber(target) else { continue }
            var dst = sockaddr_in()
            dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            dst.sin_family = sa_family_t(AF_INET)
            dst.sin_port = in_port_t(boundUdpPort).bigEndian
            dst.sin_addr = in_addr(s_addr: number)
            let sent = withUnsafePointer(to: &dst) { pointer -> ssize_t in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { name in
                    bytes.withUnsafeBufferPointer { source in
                        sendto(sk, source.baseAddress, bytes.count, 0, name, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            if sent < 0 {
                // Not fatal and not retried: one interface that refuses broadcast (a VPN, a hot spot that
                // drops it) must not stop the announcement going out over the Wi-Fi one.
                note("往 \(target) 公告失败：\(lastError())")
            } else {
                packetsSent += 1
            }
        }
    }

    /** The limited broadcast address plus the directed broadcast of every IPv4 interface up. The desktop
     *  only sends to 255.255.255.255; a phone's driver is less sure about that one, so each subnet's own
     *  broadcast goes out too. Same bytes either way, so a listener cannot tell which path delivered it.
     *
     *  `ifa_dstaddr` is the broadcast address on a broadcast interface - and on a point-to-point one it is
     *  the far end of the link, which is why `IFF_BROADCAST` is checked before the address is used. */
    private static func broadcastTargets() -> [String] {
        var out: [String] = [LIMITED_BROADCAST]
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else {
            warn("读不到网卡广播地址：\(lastError())")
            return out
        }
        defer { freeifaddrs(first) }
        var cursor = first
        while let entry = cursor {
            let flags = Int32(entry.pointee.ifa_flags)
            if let broad = entry.pointee.ifa_dstaddr,
               Int32(broad.pointee.sa_family) == AF_INET,
               flags & IFF_UP == IFF_UP,
               flags & IFF_LOOPBACK == 0,
               flags & IFF_BROADCAST == IFF_BROADCAST {
                let sin = broad.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                let text = addressText(sin.sin_addr)
                if text != "" && !out.contains(text) {
                    out.append(text)
                }
            }
            cursor = entry.pointee.ifa_next
        }
        return out
    }

    // ------------------------------------------------------------------ mDNS path

    private static func startBonjour(_ serviceType: String,
                                     _ provider: @escaping () -> String,
                                     _ inbound: @escaping (String) -> Void) {
        let held = CsDiscoveryDelegate()
        held.inbound = inbound
        delegate = held
        // Bonjour reports through a run loop, and only the main one is guaranteed to be running while the
        // page is on screen. Starting a search from this queue would hand the delegate to a thread that
        // never spins.
        DispatchQueue.main.async {
            if !running {
                return
            }
            publish(serviceType, provider)
            search(serviceType, held)
        }
    }

    /** The four TXT keys of spec §2, from the provider's `txt` array, as Bonjour wants them: raw bytes per
     *  key. A record without `fp` is a name and an address with nothing to pin, so an empty list here is
     *  reported as this channel being unavailable rather than published as a service nobody can verify. */
    private static func txtProperties(from made: [String: Any]) -> [String: Data] {
        var out: [String: Data] = [:]
        guard let list = made["txt"] as? [Any] else { return out }
        for raw in list {
            guard let entry = raw as? String else { continue }
            let parts = entry.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if parts.count == 2 && parts[0].count > 0 {
                out[String(parts[0])] = Data(String(parts[1]).utf8)
            }
        }
        return out
    }

    private static func announceJson(_ provider: () -> String) -> [String: Any]? {
        return CsBytes.object(provider())
    }

    private static func publish(_ serviceType: String, _ provider: @escaping () -> String) {
        guard let made = announceJson(provider) else {
            mdnsState = "unavailable"
            mdnsDetail = "本机公告造不出来，mDNS 这条通道没有可发布的服务"
            note(mdnsDetail)
            return
        }
        let label = (made["service"] as? String) ?? "chuanshu"
        let tls = (made["port"] as? NSNumber)?.int32Value ?? 0
        let properties = txtProperties(from: made)
        if properties.isEmpty {
            mdnsState = "unavailable"
            mdnsDetail = "mDNS 记录带不出字段，对端解析到也钉不住"
            note(mdnsDetail)
            return
        }
        let service = NetService(domain: "local", type: serviceType, name: label, port: tls)
        for (key, value) in properties {
            service.setProperty(value, forKey: key)
        }
        if let held = delegate {
            service.delegate = held
        }
        service.scheduleInRunLoop(RunLoop.main, forMode: .common)
        service.publish()
        published = service
    }

    private static func search(_ serviceType: String, _ held: CsDiscoveryDelegate) {
        let made = NetServiceBrowser()
        made.delegate = held
        made.scheduleInRunLoop(RunLoop.main, forMode: .common)
        browser = made
        made.searchForServices(ofType: serviceType, inDomain: "local")
    }

    private static func teardownBonjour() {
        let held = browser
        let service = published
        browser = nil
        published = nil
        // Dropped before the callbacks can fire again: an in-flight resolve that lands after this has
        // nowhere to deliver to, and a roster the page has already thrown away must not be written to.
        delegate?.inbound = nil
        delegate = nil
        mapLock.lock()
        prefixesByService.removeAll()
        mapLock.unlock()
        held?.stop()
        service?.stop()
    }

    /** A DNS-SD answer as the roster wants it: the TXT entries back as `k=v` strings, the address the
     *  framework resolved, and the port the service listens on. Nothing here is decided - `applyTxt` on
     *  the other side of the callback does that. */
    private static func entries(of service: NetService) -> [String] {
        var out: [String] = []
        guard let record = service.TXTRecordData() else { return out }
        let made = NetService.dictionary(fromTXTRecord: record)
        for (key, value) in made {
            if let text = String(data: value, encoding: .utf8) {
                out.append(key + "=" + text)
            }
        }
        return out
    }

    private static func hostOf(_ service: NetService) -> String {
        for raw in service.addresses ?? [] {
            let text = raw.withUnsafeBytes { pointer -> String in
                guard let base = pointer.bindMemory(to: sockaddr.self).baseAddress,
                      base.pointee.sa_family == UInt8(AF_INET) else { return "" }
                let sin = base.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                return addressText(sin.sin_addr)
            }
            // The first IPv4 address is the one the contract's hello can be dialled back to; an IPv6
            // answer would need a scope id this protocol does not carry.
            if text != "" {
                return text
            }
        }
        return ""
    }

    // ------------------------------------------------------------ delegate callbacks

    private static func deliver(_ inbound: (String) -> Void, _ text: String) {
        if !running {
            return
        }
        inbound(text)
    }

    static func didResolve(_ service: NetService, _ inbound: (String) -> Void) {
        if !running {
            return
        }
        let entries = self.entries(of: service)
        var prefix = ""
        for entry in entries where entry.hasPrefix("fp=") {
            prefix = String(entry.dropFirst(3))
        }
        if prefix != "" {
            mapLock.lock()
            prefixesByService[service.name] = prefix
            mapLock.unlock()
        }
        let host = hostOf(service)
        if host == "" || prefix == "" {
            // Either the answer carries nothing to pin (spec §2 ignores it) or nothing to dial.
            return
        }
        servicesFound += 1
        deliver(inbound, CsBytes.json([
            "via": "mdns", "kind": "got", "host": host,
            "port": Int(service.port), "txt": entries
        ] as [String: Any]))
    }

    static func didRemove(_ service: NetService, _ inbound: (String) -> Void) {
        servicesLost += 1
        mapLock.lock()
        let prefix = prefixesByService.removeValue(forKey: service.name) ?? ""
        mapLock.unlock()
        if prefix == "" {
            return
        }
        deliver(inbound, CsBytes.json(["via": "mdns", "kind": "lost", "prefix": prefix] as [String: Any]))
    }

    static func markMdnsOk(_ line: String) {
        if mdnsState != "ok" {
            mdnsState = "ok"
            mdnsDetail = ""
        }
        note(line)
    }

    static func markMdnsDown(_ line: String) {
        mdnsState = "unavailable"
        mdnsDetail = line
        note(line)
    }

    static func noteLine(_ line: String) {
        note(line)
    }
}

/** Bonjour hands both the browser's answers and our own publish result to one delegate object, and Swift
 *  needs an `NSObject` subclass for that. It holds no state of its own: everything it learns is passed to
 *  `CsDiscovery`, which is where the roster's owner put the callbacks in the first place. */
final class CsDiscoveryDelegate: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {

    var inbound: ((String) -> Void)?

    func netServiceBrowserWillSearch(_ browser: NetServiceBrowser) {
        CsDiscovery.markMdnsOk("mDNS 正在搜索")
    }

    func netServiceBrowserDidStopSearch(_ browser: NetServiceBrowser) {
        CsDiscovery.noteLine("mDNS 搜索已停止")
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        CsDiscovery.markMdnsDown("mDNS 搜索没能开始：\(errorDict)")
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        // A found record carries no TXT and sometimes no address; resolving it is what makes it a
        // candidate, and the answer comes back on the same delegate.
        service.delegate = self
        service.scheduleInRunLoop(RunLoop.main, forMode: .common)
        service.resolve(withTimeout: 5.0)
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        guard let sink = inbound else { return }
        CsDiscovery.didRemove(service, sink)
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        guard let sink = inbound else { return }
        CsDiscovery.didResolve(sender, sink)
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        // A service that cannot be resolved is not a candidate: no address, no TXT, nothing to verify.
        // Counted as a note so the panel's log can say why a device blinked and vanished.
        CsDiscovery.noteLine("解析 \(sender.name) 失败：\(errorDict)")
    }

    func netServiceDidPublish(_ sender: NetService) {
        CsDiscovery.markMdnsOk("mDNS 已注册 \(sender.name)")
    }

    func netService(_ sender: NetService, didNotPublish errorDict: [String: NSNumber]) {
        CsDiscovery.markMdnsDown("mDNS 注册失败：\(errorDict)")
    }

    func netServiceDidStop(_ sender: NetService) {
        CsDiscovery.noteLine("mDNS 已注销")
    }
}
