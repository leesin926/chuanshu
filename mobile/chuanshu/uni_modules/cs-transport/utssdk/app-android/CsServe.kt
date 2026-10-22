package uts.sdk.modules.csTransport

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/** The phone as the peer that gets connected *to*: one TLS listener on the transport port, one thread
 *  per connection, and every request handed to the same state machine the browser drives
 *  (utssdk/cs-receive.uts). The listener adds nothing to the protocol; it only moves bytes.
 *
 *  Two things here are deliberate:
 *
 *  - No read timeout on the connection. A 4 MiB chunk body can outlast any timeout small enough to be
 *    worth setting, and the honest end of a conversation is the socket closing - `readLine` returns null
 *    the moment the peer hangs up. `stop()` closes everything still open, so no connection outlives the
 *    listener it came in through.
 *  - One lock around the state machine. The web host has JavaScript's single thread for free; here a
 *    connection worker and the UI both touch the same inbox, so `gate()` is how UTS says "this is the
 *    critical section". */
object CsServe {

    private val lock = ReentrantLock()
    private val counter = AtomicInteger(1)
    private val blobs = ConcurrentHashMap<Int, ByteArray>()
    private val open = Collections.synchronizedSet(mutableSetOf<SSLSocket>())
    private val notes = JSONArray()

    @Volatile
    private var server: SSLServerSocket? = null

    @Volatile
    private var running = false

    private fun note(text: String) {
        synchronized(notes) {
            notes.put(text)
            while (notes.length() > 24) {
                notes.remove(0)
            }
        }
    }

    fun noteLog(): String = synchronized(notes) { notes.toString() }

    fun isRunning(): Boolean = running

    fun port(): Int = try {
        server?.localPort ?: 0
    } catch (e: Throwable) {
        0
    }

    /** Run the shared state machine's access under the listener's lock. UTS calls this with the body
     *  that touches the inbox, so a chunk landing on a worker thread cannot interleave with the user
     *  tapping 接受. */
    fun gate(body: () -> String): String {
        lock.lock()
        return try {
            body()
        } finally {
            lock.unlock()
        }
    }

    /** The binary body of the request at `index`, consumed once. A 4 MiB chunk crosses as a ByteBuffer
     *  instead of as base64 inside the request JSON, because the sender's digest is over these exact
     *  bytes and a text round trip would only add a way to get them wrong. */
    fun takeBlob(index: Number): ByteBuffer? {
        val raw = blobs.remove(index.toInt()) ?: return null
        return ByteBuffer.wrap(raw)
    }

    // -------------------------------------------------------------------- request parsing

    private fun readLine(ins: InputStream): String? {
        val out = StringBuilder()
        while (true) {
            val b = ins.read()
            if (b < 0) return if (out.isEmpty()) null else out.toString()
            if (b == '\n'.code) {
                if (out.isNotEmpty() && out.last() == '\r') out.deleteCharAt(out.length - 1)
                return out.toString()
            }
            out.append(b.toChar())
            if (out.length > 8192) throw IOException("请求头过长")
        }
    }

    private fun readExactly(ins: InputStream, count: Int): ByteArray {
        val out = ByteArray(count)
        var done = 0
        while (done < count) {
            val n = ins.read(out, done, count - done)
            if (n < 0) break
            done += n
        }
        return if (done == count) out else out.copyOf(done)
    }

    private fun valueOf(line: String, name: String): String {
        val lower = line.lowercase()
        if (!lower.startsWith(name)) return ""
        return line.substring(name.length).trim()
    }

    /** `0x1B 0x1B` means a literal escape and `0x1B B` means a zero byte; a trailing or unknown escape is
     *  left as the byte it is, exactly as `app/net/spec.py:unescape_chunk` reads it. The desktop escapes
     *  every PUT body that contains a zero byte and declares it in `X-Chunk-Escape` (spec §4), and the
     *  digest the sender puts in `X-Sha256` is over the plain bytes - so a receiver that ignores this
     *  header stores the escaped ones under a hash they do not match, and every such chunk is rejected. */
    private fun unescape(bytes: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(bytes.size)
        var at = 0
        while (at < bytes.size) {
            if (bytes[at] != 0x1b.toByte()) {
                out.write(bytes[at].toInt())
                at += 1
                continue
            }
            if (at + 1 >= bytes.size) {
                out.write(0x1b)
                at += 1
                continue
            }
            val next = bytes[at + 1]
            when {
                next == 0x1b.toByte() -> out.write(0x1b)
                next == 'B'.code.toByte() -> out.write(0)
                else -> {
                    out.write(0x1b)
                    out.write(next.toInt())
                }
            }
            at += 2
        }
        return out.toByteArray()
    }

    // -------------------------------------------------------------------- response writing

    private fun reasonOf(status: Int): String = when (status) {
        200 -> "OK"
        400 -> "Bad Request"
        403 -> "Forbidden"
        404 -> "Not Found"
        422 -> "Unprocessable Entity"
        429 -> "Too Many Requests"
        507 -> "Insufficient Storage"
        else -> "Status"
    }

    private fun writeResponse(sk: SSLSocket, status: Int, body: String) {
        val raw = body.toByteArray(Charsets.UTF_8)
        val head = StringBuilder()
            .append("HTTP/1.1 $status ${reasonOf(status)}\r\n")
            .append("Content-Type: application/json\r\n")
            .append("Content-Length: ${raw.size}\r\n")
            .append("Connection: close\r\n\r\n")
        val out = sk.getOutputStream()
        out.write(head.toString().toByteArray(Charsets.US_ASCII))
        out.write(raw)
        out.flush()
    }

    // -------------------------------------------------------------------- one connection

    private fun isJsonBody(method: String, contentType: String): Boolean =
        method != "PUT" || contentType.contains("json")

    private fun serveOne(sk: SSLSocket, handler: (String) -> String) {
        var index = 0
        try {
            sk.startHandshake()
            val ins = sk.getInputStream()
            val line0 = readLine(ins) ?: return
            val bits = line0.split(" ")
            if (bits.size < 2) {
                note("请求行读不出方法：$line0")
                return
            }
            val method = bits[0]
            val path = bits[1]
            var token = ""
            var sha = ""
            var type = ""
            var escape = ""
            var declared = -1
            while (true) {
                val line = readLine(ins) ?: break
                if (line.isEmpty()) break
                val lower = line.lowercase()
                if (lower.startsWith("content-length:")) {
                    declared = valueOf(line, "content-length:").toIntOrNull() ?: -1
                } else if (lower.startsWith("x-chuanshu-auth:")) {
                    token = valueOf(line, "x-chuanshu-auth:")
                } else if (lower.startsWith("x-sha256:")) {
                    sha = valueOf(line, "x-sha256:")
                } else if (lower.startsWith("x-chunk-escape:")) {
                    escape = valueOf(line, "x-chunk-escape:")
                } else if (lower.startsWith("content-type:")) {
                    type = valueOf(line, "content-type:")
                }
            }
            val wire = if (declared > 0) readExactly(ins, declared) else ByteArray(0)
            val raw = if (escape.isNotEmpty() && method == "PUT" && wire.isNotEmpty()) {
                val plain = unescape(wire)
                note("反解 $escape：收到 ${wire.size} 解出 ${plain.size}")
                plain
            } else {
                wire
            }
            index = counter.getAndIncrement()
            val jsonish = raw.isEmpty() || isJsonBody(method, type)
            if (!jsonish) {
                blobs[index] = raw
            }
            val client = try {
                sk.inetAddress?.hostAddress ?: "?"
            } catch (e: Throwable) {
                "?"
            }
            val request = JSONObject()
                .put("index", index)
                .put("method", method)
                .put("path", path)
                .put("token", token)
                .put("sha", sha)
                .put("client", client)
                .put("json", if (jsonish) String(raw, Charsets.UTF_8) else "")
                .put("blob", if (jsonish) 0 else raw.size)
            val answer = handler(request.toString())
            val reply = try {
                JSONObject(answer)
            } catch (e: Throwable) {
                note("状态机的应答不是 JSON：$answer")
                return
            }
            val status = reply.optInt("status", 400)
            val body = reply.optString("body", "{}")
            // An offer that needs a person is answered on the spot with "nobody has decided yet": the
            // sender polls a fresh connection until the card is tapped, because holding this one open
            // for an answer loses both the answer and the connection (task #59, measured on a phone).
            writeResponse(sk, status, body)
        } catch (e: Throwable) {
            note("这条连接断开：$e")
        } finally {
            blobs.remove(index)
            try {
                sk.close()
            } catch (ignored: Throwable) {
            }
        }
    }

    // -------------------------------------------------------------------- the listener

    /** TLS needs our key and a certificate whose public key is the one both ends have been hashing.
     *  Parsed through CertificateFactory rather than handed to the keystore as raw DER: a builder-made
     *  wrapper is what made the desktop side answer "No available authentication scheme". */
    private fun context(): SSLContext {
        val der = CsIdentity.certDer()
        val parsed = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val key = CsIdentity.privateKey()
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("p", key, CharArray(0), arrayOf<Certificate>(parsed))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, CharArray(0))
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        return ctx
    }

    fun start(port: Number, handler: (String) -> String): String {
        if (running) {
            return JSONObject().put("listening", port()).toString()
        }
        return try {
            val srv = context().serverSocketFactory.createServerSocket() as SSLServerSocket
            srv.enabledCipherSuites = srv.supportedCipherSuites
            srv.bind(InetSocketAddress(port.toInt()))
            server = srv
            running = true
            note("开始监听 ${srv.localPort}")
            val t = Thread {
                while (running) {
                    val sk = try {
                        srv.accept() as SSLSocket
                    } catch (e: Throwable) {
                        if (running) {
                            note("一次接入失败：$e")
                        }
                        break
                    }
                    open.add(sk)
                    Thread {
                        serveOne(sk, handler)
                        open.remove(sk)
                    }.start()
                }
                running = false
            }
            t.isDaemon = true
            t.start()
            JSONObject().put("listening", srv.localPort).toString()
        } catch (e: Throwable) {
            note("监听没能起来：$e")
            JSONObject().put("error", "$e").toString()
        }
    }

    /** Closing the listener wakes the accept loop, and every connection still open is closed with it -
     *  a sender must never be left holding a socket to a phone that decided to stop receiving. */
    fun stop(): String {
        running = false
        var closed = 0
        try {
            server?.close()
        } catch (ignored: Throwable) {
        }
        server = null
        synchronized(open) {
            for (sk in open) {
                try {
                    sk.close()
                } catch (ignored: Throwable) {
                }
                closed++
            }
            open.clear()
        }
        note("已经不再监听")
        return JSONObject().put("stopped", true).put("closed", closed).toString()
    }

    /** Seconds since the epoch, from Kotlin, so the state machine and the listener agree on the clock
     *  without UTS having to trust `Date.now()` on a backgrounded app. */
    fun nowSeconds(): Long = System.currentTimeMillis() / 1000L
}
