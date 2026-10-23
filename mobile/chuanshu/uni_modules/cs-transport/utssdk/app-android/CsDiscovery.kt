package uts.sdk.modules.csTransport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import io.dcloud.uts.UTSAndroid
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** The phone's half of discovery: two sockets and a name, nothing else.
 *
 *  Everything that *decides* - merging by fingerprint prefix, expiring a silent peer, refusing a
 *  version this build cannot speak, filtering out our own broadcast - lives in utssdk/cs-discovery.uts
 *  and runs identically in the browser. This file moves bytes and reports what it had to do about
 *  them. It never parses an announcement and never holds a roster, because a phone that grew its own
 *  merge rules would be a phone the PC cannot be found by.
 *
 *  Two channels, both required by spec §2, with different failure shapes:
 *
 *  - UDP broadcast on 43721 needs a socket that may broadcast (`SO_BROADCAST`) before it is bound, and
 *    a multicast lock, because Android's Wi-Fi power save drops received broadcasts when the screen is
 *    off. Failing to get the lock is reported, not swallowed: the socket looks fine and hears nothing.
 *  - NsdManager needs a Looper for its callbacks, so every registration and browse is posted to the
 *    main thread; and its TXT record only exists from Android 9. Below that this channel is named as
 *    unavailable rather than quietly registering a service nobody can read.
 *
 *  The escape route is the pairing QR and the typed address, and both work when neither channel does -
 *  which is why a dead channel is a sentence in the UI (`status()`), not a silent empty list. */
object CsDiscovery {

    private const val MAX_PACKET = 4096
    private const val LIMITED_BROADCAST = "255.255.255.255"

    private val main = Handler(Looper.getMainLooper())
    private val notes = JSONArray()
    private val warnings = mutableListOf<String>()
    private val inboundLock = Any()

    @Volatile
    private var running = false

    @Volatile
    private var socket: DatagramSocket? = null

    private var multicast: WifiManager.MulticastLock? = null
    private var nsd: NsdManager? = null
    private var registration: NsdManager.RegistrationListener? = null
    private var discovery: NsdManager.DiscoveryListener? = null

    /** A DNS-SD goodbye names the service, not the machine, and the roster is keyed by fingerprint
     *  prefix - so the name that resolved to which prefix is remembered here, exactly as the PC's
     *  `_mdns_names` does. Only touched on the main thread, which is where every Nsd callback runs. */
    private val prefixesByService = HashMap<String, String>()

    private val bytesIn = AtomicInteger(0)
    private val packetsSent = AtomicInteger(0)
    private val servicesFound = AtomicInteger(0)
    private val servicesLost = AtomicInteger(0)

    @Volatile
    private var udpState = "stopped"

    @Volatile
    private var udpDetail = ""

    @Volatile
    private var mdnsState = "stopped"

    @Volatile
    private var mdnsDetail = ""

    private fun note(text: String) {
        synchronized(notes) {
            notes.put(text)
            while (notes.length() > 24) {
                notes.remove(0)
            }
        }
    }

    private fun warn(text: String) {
        val fresh = synchronized(warnings) {
            if (warnings.contains(text) || warnings.size >= 6) {
                false
            } else {
                warnings.add(text)
                true
            }
        }
        if (fresh) {
            note("警告：$text")
        }
    }

    // ------------------------------------------------------------------ lifecycle

    /** @param port the discovery datagram port (contract `ports.discovery_udp`; it may not fall back)
     *  @param intervalS how often to re-announce (contract `discovery.announce_interval_s`)
     *  @param serviceType DNS-SD type, e.g. `_chuanshu._tcp.`
     *  @param provider builds one announcement: `{"announce":text,"service":name,"port":tls,"txt":[…]}`
     *  @param inbound every packet and every DNS-SD answer, as `{"via":…}` JSON
     *
     *  The provider and the inbound sink are UTS functions called from threads this object owns, so
     *  neither may touch a UI. The roster they reach is guarded by CsServe.gate() on the UTS side. */
    fun start(
        port: Number,
        intervalS: Number,
        serviceType: String,
        provider: () -> String,
        inbound: (String) -> Unit
    ): String {
        if (running) {
            return status()
        }
        running = true
        bytesIn.set(0)
        packetsSent.set(0)
        servicesFound.set(0)
        servicesLost.set(0)
        synchronized(inboundLock) {
            prefixesByService.clear()
        }
        synchronized(warnings) {
            warnings.clear()
        }
        startUdp(port.toInt(), intervalS.toLong(), provider, inbound)
        startMdns(serviceType, provider, inbound)
        note("发现已启动（广播端口 ${port.toInt()}，服务类型 $serviceType）")
        return status()
    }

    fun stop(): String {
        if (!running) {
            return status()
        }
        running = false
        val held = socket
        socket = null
        try {
            held?.close()
        } catch (e: Throwable) {
            note("广播套接字没能关干净：$e")
        }
        val latch = CountDownLatch(1)
        main.post {
            teardownMdns()
            latch.countDown()
        }
        try {
            latch.await(1500, TimeUnit.MILLISECONDS)
        } catch (e: Throwable) {
            note("mDNS 取消注册没等到回执")
        }
        releaseMulticast()
        udpState = "stopped"
        udpDetail = ""
        mdnsState = "stopped"
        mdnsDetail = ""
        note("发现已停止")
        return status()
    }

    fun isRunning(): Boolean = running

    /** Channels, counters and the last lines of what happened - the panel shows `detail` when a path
     *  is down, because "发现不到设备" is not an actionable sentence and "mDNS 不可用：…，可以用配对二维
     *  码" is. */
    fun status(): String {
        val warned = JSONArray()
        synchronized(warnings) {
            warnings.forEach { warned.put(it) }
        }
        val lines = JSONArray()
        synchronized(notes) {
            for (index in 0 until notes.length()) {
                lines.put(notes.optString(index))
            }
        }
        return JSONObject()
            .put("udp", JSONObject().put("state", udpState).put("detail", udpDetail))
            .put("mdns", JSONObject().put("state", mdnsState).put("detail", mdnsDetail))
            .put("warnings", warned)
            .put("counts", JSONObject()
                .put("bytes_in", bytesIn.get())
                .put("sent", packetsSent.get())
                .put("found", servicesFound.get())
                .put("lost", servicesLost.get()))
            .put("notes", lines)
            .toString()
    }

    // ------------------------------------------------------------------- UDP path

    private fun unbound(): DatagramSocket? =
        try {
            // Bound only after the options are set: SO_BROADCAST has to be on the socket before it can
            // answer a 255.255.255.255 send, and SO_REUSEADDR is what lets a restart re-take the port
            // while the previous listener is still on the way out.
            DatagramSocket(null).apply {
                reuseAddress = true
                broadcast = true
            }
        } catch (e: Throwable) {
            note("广播套接字创建失败：$e")
            null
        }

    private fun startUdp(
        port: Int,
        intervalS: Long,
        provider: () -> String,
        inbound: (String) -> Unit
    ) {
        val sk = unbound()
        if (sk == null) {
            udpState = "unavailable"
            udpDetail = "广播套接字创建失败"
            return
        }
        try {
            sk.bind(InetSocketAddress(port))
            sk.soTimeout = 1000
        } catch (e: Throwable) {
            try {
                sk.close()
            } catch (_: Throwable) {
            }
            udpState = "unavailable"
            udpDetail = "$e"
            note("广播端口 $port 没能绑上：$e")
            return
        }
        socket = sk
        udpState = "ok"
        udpDetail = ""
        takeMulticast()
        val listen = Thread({
            while (running) {
                val live = socket ?: break
                val bag = ByteArray(MAX_PACKET)
                val packet = DatagramPacket(bag, bag.size)
                try {
                    live.receive(packet)
                } catch (e: SocketTimeoutException) {
                    continue
                } catch (e: Throwable) {
                    if (running) {
                        note("广播收包中断：$e")
                        udpState = "unavailable"
                        udpDetail = "$e"
                    }
                    break
                }
                val from = packet.address
                if (from !is Inet4Address) {
                    // An IPv6 announcement would need a scope id to be reachable, and the contract's
                    // hello path has none. Ignored rather than dialled wrong.
                    continue
                }
                bytesIn.addAndGet(packet.length)
                val text = String(packet.data, packet.offset, packet.length, StandardCharsets.UTF_8)
                deliver(inbound, JSONObject()
                    .put("via", "udp")
                    .put("host", from.hostAddress ?: "")
                    .put("text", text)
                    .toString())
            }
        }, "chuanshu-udp-listen")
        listen.isDaemon = true
        val announce = Thread({
            // One packet up front, then the contract's interval: a phone that just joined the network
            // should appear on the desktop within a second, not after the first full interval.
            while (running) {
                announceOnce(provider)
                try {
                    Thread.sleep(intervalS.coerceAtLeast(1L) * 1000L)
                } catch (e: InterruptedException) {
                    break
                }
            }
        }, "chuanshu-announce")
        announce.isDaemon = true
        listen.start()
        announce.start()
    }

    private fun announceOnce(provider: () -> String) {
        val held = socket ?: return
        val text = try {
            provider()
        } catch (e: Throwable) {
            note("本机公告造不出来：$e")
            return
        }
        if (text == "") {
            return
        }
        val made = try {
            JSONObject(text)
        } catch (e: Throwable) {
            return
        }
        val body = made.optString("announce").toByteArray(StandardCharsets.UTF_8)
        if (body.isEmpty()) {
            return
        }
        for (target in broadcastTargets()) {
            try {
                held.send(DatagramPacket(body, body.size, InetAddress.getByName(target), held.localPort))
                packetsSent.incrementAndGet()
            } catch (e: Throwable) {
                // Not fatal and not retried: one dead interface (a VPN that refuses broadcast) must
                // not stop the announcement going out over the Wi-Fi one.
                note("往 $target 公告失败：$e")
            }
        }
    }

    /** The limited broadcast address plus the directed broadcast of every IPv4 interface up. The PC
     *  only uses 255.255.255.255; a phone's driver is less sure about that one, so the subnet address
     *  goes out too. Both carry the same bytes, so a listener cannot tell which path delivered it. */
    private fun broadcastTargets(): List<String> {
        val out = LinkedHashSet<String>()
        out.add(LIMITED_BROADCAST)
        try {
            val faces = NetworkInterface.getNetworkInterfaces()
            while (faces.hasMoreElements()) {
                val face = faces.nextElement() ?: continue
                if (!face.isUp || face.isLoopback) {
                    continue
                }
                for (address in face.interfaceAddresses) {
                    if (address.address !is Inet4Address) {
                        continue
                    }
                    address.broadcast?.let { out.add(it.hostAddress ?: "") }
                }
            }
        } catch (e: Throwable) {
            warn("读不到网卡广播地址：$e")
        }
        out.remove("")
        return out.toList()
    }

    private fun takeMulticast() {
        val made = try {
            val wifi = UTSAndroid.getAppContext()?.applicationContext
                ?.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            wifi?.createMulticastLock("chuanshu-discovery")?.apply {
                // Not reference counted: this phone has one discovery service, and a leak here would
                // keep the Wi-Fi radio awake for a listener that has already been stopped.
                setReferenceCounted(false)
                acquire()
            }
        } catch (e: Throwable) {
            note("组播锁没拿到：$e")
            null
        }
        if (made == null) {
            warn("组播锁没拿到：息屏时收到的广播可能被系统丢掉")
        } else {
            multicast = made
            note("组播锁已持有")
        }
    }

    private fun releaseMulticast() {
        val held = multicast
        multicast = null
        try {
            held?.release()
        } catch (_: Throwable) {
        }
    }

    // ------------------------------------------------------------------ mDNS path

    private fun startMdns(
        serviceType: String,
        provider: () -> String,
        inbound: (String) -> Unit
    ) {
        if (Build.VERSION.SDK_INT < 28) {
            // Android only exposes a DNS-SD TXT record from API 28. Without `fp` a resolved service is
            // a name and an address with nothing to pin, and spec §2 says presence is not trust - so
            // this path is named as unavailable and the phone leans on the broadcast and the QR.
            mdnsState = "unavailable"
            mdnsDetail = "这台系统的 mDNS 记录带不出指纹前缀（需要 Android 9 以上）"
            note(mdnsDetail)
            return
        }
        val manager = try {
            UTSAndroid.getAppContext()?.getSystemService(Context.NSD_SERVICE) as? NsdManager
        } catch (e: Throwable) {
            mdnsState = "unavailable"
            mdnsDetail = "$e"
            return
        }
        if (manager == null) {
            mdnsState = "unavailable"
            mdnsDetail = "系统没有提供 NSD 服务"
            return
        }
        nsd = manager
        // NsdManager builds a Handler on the calling thread's Looper. This runs on the discovery
        // starter's thread, which has none, so the calls belong on the main one.
        main.post {
            if (!running) {
                return@post
            }
            register(serviceType, provider)
            browse(serviceType, inbound)
        }
    }

    /** The SDK stub this build compiles against declares `getAttributes` but no `setAttributes`, so the
     *  TXT map is put by name. Android only carries DNS-SD attributes from API 28, and a service
     *  registered without `fp` is a name and an address with nothing to pin - which is why a method that
     *  cannot be found is reported as this channel being unavailable rather than swallowed. */
    private fun applyAttributes(info: NsdServiceInfo, attributes: Map<String, ByteArray>): String =
        try {
            info.javaClass.getMethod("setAttributes", Map::class.java).invoke(info, attributes)
            ""
        } catch (e: Throwable) {
            "$e"
        }

    private fun register(serviceType: String, provider: () -> String) {
        val manager = nsd ?: return
        val text = try {
            provider()
        } catch (e: Throwable) {
            mdnsState = "unavailable"
            mdnsDetail = "本机公告造不出来：$e"
            return
        }
        val made = try {
            JSONObject(text)
        } catch (e: Throwable) {
            mdnsState = "unavailable"
            mdnsDetail = "本机公告不是 JSON"
            return
        }
        val info = NsdServiceInfo().apply {
            serviceName = made.optString("service", "chuanshu")
            this.serviceType = serviceType
            port = made.optInt("port", 0)
        }
        val attributes = HashMap<String, ByteArray>()
        val list = made.optJSONArray("txt")
        if (list != null) {
            for (index in 0 until list.length()) {
                val entry = list.optString(index)
                val eq = entry.indexOf('=')
                if (eq <= 0) {
                    continue
                }
                attributes[entry.substring(0, eq)] = entry.substring(eq + 1).toByteArray(StandardCharsets.UTF_8)
            }
        }
        val rejected = applyAttributes(info, attributes)
        if (rejected != "") {
            mdnsState = "unavailable"
            mdnsDetail = "mDNS 记录带不出字段：$rejected"
            note(mdnsDetail)
            return
        }
        val listener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(info: NsdServiceInfo?) {
                mdnsState = "ok"
                mdnsDetail = ""
                note("mDNS 已注册 ${info?.serviceName ?: ""}")
            }

            override fun onRegistrationFailed(info: NsdServiceInfo?, errorCode: Int) {
                mdnsState = "unavailable"
                mdnsDetail = "mDNS 注册失败（错误码 $errorCode）"
                note(mdnsDetail)
            }

            override fun onServiceUnregistered(info: NsdServiceInfo?) {
                note("mDNS 已注销")
            }

            override fun onUnregistrationFailed(info: NsdServiceInfo?, errorCode: Int) {
                note("mDNS 注销失败（错误码 $errorCode）")
            }
        }
        registration = listener
        try {
            manager.registerService(info, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Throwable) {
            mdnsState = "unavailable"
            mdnsDetail = "$e"
            note("mDNS 注册没发出去：$e")
        }
    }

    private fun browse(serviceType: String, inbound: (String) -> Unit) {
        val manager = nsd ?: return
        val resolveListener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(info: NsdServiceInfo?, errorCode: Int) {
                // A service that cannot be resolved is not a candidate: no address, no TXT, nothing to
                // verify. Counted as a note so the panel's log can say why a device blinked and vanished.
                note("解析 ${info?.serviceName ?: "?"} 失败（错误码 $errorCode）")
            }

            override fun onServiceResolved(info: NsdServiceInfo?) {
                if (info == null || !running) {
                    return
                }
                val entries = txtEntries(info)
                val prefix = entries.firstOrNull { it.startsWith("fp=") }?.substring(3) ?: ""
                if (prefix != "") {
                    synchronized(inboundLock) {
                        prefixesByService[info.serviceName ?: ""] = prefix
                    }
                }
                val host = info.host?.hostAddress ?: ""
                if (host == "" || prefix == "") {
                    // Either the answer carries nothing to pin (spec §2 ignores it) or nothing to dial.
                    return
                }
                servicesFound.incrementAndGet()
                val txt = JSONArray()
                entries.forEach { txt.put(it) }
                deliver(inbound, JSONObject()
                    .put("via", "mdns")
                    .put("kind", "got")
                    .put("host", host)
                    .put("port", info.port)
                    .put("txt", txt)
                    .toString())
            }
        }
        val listener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(type: String?, errorCode: Int) {
                mdnsState = "unavailable"
                mdnsDetail = "mDNS 搜索启动失败（错误码 $errorCode）"
                note(mdnsDetail)
            }

            override fun onStopDiscoveryFailed(type: String?, errorCode: Int) {
                note("mDNS 搜索停止失败（错误码 $errorCode）")
            }

            override fun onDiscoveryStarted(type: String?) {
                if (mdnsState == "stopped" || mdnsState == "unavailable") {
                    mdnsState = "ok"
                    mdnsDetail = ""
                }
                note("mDNS 正在搜索 $type")
            }

            override fun onDiscoveryStopped(type: String?) {
                note("mDNS 搜索已停止")
            }

            override fun onServiceFound(info: NsdServiceInfo?) {
                val manager = nsd ?: return
                if (info == null || !running) {
                    return
                }
                try {
                    @Suppress("DEPRECATION")
                    manager.resolveService(info, resolveListener)
                } catch (e: Throwable) {
                    note("mDNS 解析发不出去：$e")
                }
            }

            override fun onServiceLost(info: NsdServiceInfo?) {
                val name = info?.serviceName ?: ""
                val prefix = synchronized(inboundLock) { prefixesByService.remove(name) } ?: ""
                servicesLost.incrementAndGet()
                if (prefix == "") {
                    return
                }
                deliver(inbound, JSONObject()
                    .put("via", "mdns")
                    .put("kind", "lost")
                    .put("prefix", prefix)
                    .toString())
            }
        }
        discovery = listener
        try {
            // Android throws if the same listener instance is registered twice, which is exactly what a
            // stop/start inside one screen would do if the previous cancel had not landed yet.
            manager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Throwable) {
            mdnsState = "unavailable"
            mdnsDetail = "$e"
            note("mDNS 搜索没发出去：$e")
        }
    }

    private fun txtEntries(info: NsdServiceInfo): List<String> {
        val out = mutableListOf<String>()
        val attributes = try {
            info.attributes
        } catch (e: Throwable) {
            warn("mDNS 记录读不出 TXT：$e")
            null
        } ?: return out
        for ((key, value) in attributes) {
            out.add("$key=${String(value, StandardCharsets.UTF_8)}")
        }
        return out
    }

    private fun teardownMdns() {
        val manager = nsd
        val held = discovery
        val reg = registration
        // Cleared before the callbacks can fire again: an in-flight resolve that lands after this has
        // nowhere to deliver to, and a roster the page has already thrown away must not be written to.
        discovery = null
        registration = null
        nsd = null
        try {
            if (manager != null && held != null) {
                manager.stopServiceDiscovery(held)
            }
        } catch (e: Throwable) {
            note("mDNS 搜索取消失败：$e")
        }
        try {
            if (manager != null && reg != null) {
                manager.unregisterService(reg)
            }
        } catch (e: Throwable) {
            note("mDNS 注册取消失败：$e")
        }
        synchronized(inboundLock) {
            prefixesByService.clear()
        }
    }

    private fun deliver(inbound: (String) -> Unit, text: String) {
        if (!running) {
            return
        }
        try {
            inbound(text)
        } catch (e: Throwable) {
            // The roster is the caller's; a throw there is its bug and must not take the listener with
            // it. That is the same reason the PC catches around the whole receive loop.
            note("发现回调抛了：$e")
        }
    }
}
