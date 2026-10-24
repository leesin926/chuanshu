package uts.sdk.modules.csTransport

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import io.dcloud.uts.UTSAndroid
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/** Moving bytes to a peer that must be the one we chose: one TLS connection per request, pinned by
 *  the SHA-256 of the leaf's SubjectPublicKeyInfo, and file reads that work for both a real path and
 *  the content:// URIs Android's picker hands back.
 *
 *  Kotlin rather than UTS for two reasons: `X509TrustManager`'s methods take native arrays, which UTS
 *  cannot implement, and a 4 MiB chunk must not be copied through a typed-array boundary to get onto
 *  the wire. */
object CsWire {

    private const val HEX = "0123456789abcdef"
    private const val CONNECT_TIMEOUT_MS = 8000

    private fun hexOf(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(HEX[v shr 4]).append(HEX[v and 0x0f])
        }
        return out.toString()
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun bytesOf(buffer: ByteBuffer?): ByteArray {
        if (buffer == null) return ByteArray(0)
        val copy = buffer.duplicate()
        copy.rewind()
        val out = ByteArray(copy.remaining())
        copy.get(out)
        return out
    }

    // -------------------------------------------------------------------- write pace

    /** Largest plaintext a TLS record is allowed to carry on the way out. One `write` of a whole 4 MiB
     *  chunk makes records as big as the SSL engine's buffer, and a Harmony receiver does not survive
     *  that: the declared byte count arrives, the content does not, and the receiving process can go
     *  down with the attempt (protocol spec §4, `.probe/records.py`, `.probe/crashlog.py`).
     *  The record *count* is irrelevant - only the rate is. */
    private const val MAX_TLS_RECORD_PLAINTEXT = 4096

    /** The floors a Harmony receiver was measured against, per 4 KiB record: full speed corrupts,
     *  15 ms is byte-identical, 40 ms is the last resort. */
    private val PACE_LADDER = listOf(0, 15, 40)

    /** One floor per peer address, and never handed back for as long as this process lives: the run
     *  that wrote faster is the one that killed the peer, which leaves nothing to learn from. Keyed by
     *  address so a PC that asked for full speed does not inherit a courtesy owed to a phone. */
    private val paceFloors = ConcurrentHashMap<String, Int>()

    private fun paceKey(host: String, port: Int) = "$host:$port"

    private fun paceOf(host: String, port: Int): Int = paceFloors[paceKey(host, port)] ?: 0

    private fun raisePace(host: String, port: Int, ms: Int) {
        if (ms > paceOf(host, port)) paceFloors[paceKey(host, port)] = ms
    }

    /** One rung slower for this peer, nothing when the ladder is spent. A chunk whose bytes all counted
     *  but whose digest does not match, or one whose body died halfway in, is the same complaint: this
     *  pipe cannot drain at this rate, and slowing down is the only repair that needs no help from the
     *  peer. The caller resends that chunk, so the retry walks at the new floor. */
    private fun slowPipe(host: String, port: Int) {
        val now = paceOf(host, port)
        PACE_LADDER.firstOrNull { it > now }?.let { paceFloors[paceKey(host, port)] = it }
    }

    private fun writePaced(out: OutputStream, data: ByteArray, paceMs: Long) {
        var at = 0
        while (at < data.size) {
            val end = minOf(at + MAX_TLS_RECORD_PLAINTEXT, data.size)
            out.write(data, at, end - at)
            at = end
            if (at < data.size && paceMs > 0) Thread.sleep(paceMs)
        }
        out.flush()
    }

    // -------------------------------------------------------------------- pinning

    /** A trust manager that answers one question: is this the key we pinned?
     *
     *  An empty pin means first contact, where the QR's own fingerprint has not been seen yet -
     *  the pair code is what carries the trust there, and spec §3 keeps this end from ever sending a
     *  file before the peer's fingerprint has been written to the trust store. */
    private class PinTrust(private val pinHex: String) : X509TrustManager {
        var seen: String = ""

        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
            throw CertificateException("传书不对端验证客户端证书")
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull() ?: throw CertificateException("对端没有交证书")
            val got = hexOf(sha256(leaf.publicKey.encoded))
            seen = got
            if (pinHex.isNotEmpty() && !got.equals(pinHex, ignoreCase = true)) {
                throw CertificateException("期望 $pinHex，收到 $got")
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private class Pinned(val socket: SSLSocket, val trust: PinTrust)

    private fun openSocket(host: String, port: Int, pinHex: String): Pinned {
        val trust = PinTrust(pinHex)
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(trust), SecureRandom())
        val socket = ctx.socketFactory.createSocket() as SSLSocket
        socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
        // The certificate's CN is the peer_id, not a hostname, so URI matching would reject every
        // real peer. Identity is the pinned SPKI digest, checked in the trust manager.
        socket.sslParameters = socket.sslParameters.apply {
            endpointIdentificationAlgorithm = ""
        }
        socket.startHandshake()
        return Pinned(socket, trust)
    }

    // -------------------------------------------------------------------- HTTP/1.1

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
            if (out.length > 8192) throw IOException("响应头过长")
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

    private fun readAll(ins: InputStream): ByteArray {
        val sink = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = ins.read(buf)
            if (n < 0) break
            sink.write(buf, 0, n)
        }
        return sink.toByteArray()
    }

    private fun errorOf(e: Throwable, host: String): String {
        val root: Throwable = generateSequence(e) { it.cause }.last()
        return when (root) {
            is CertificateException -> JSONObject()
                .put("error", "TLS_PIN_MISMATCH").put("detail", root.message ?: "").toString()
            is UnknownHostException -> JSONObject()
                .put("error", "HOST_UNKNOWN").put("detail", host).toString()
            is java.net.ConnectException -> JSONObject()
                .put("error", "CONN_REFUSED").put("detail", "$host: ${root.message}").toString()
            is SocketException -> JSONObject()
                .put("error", "CONN_RESET").put("detail", root.message ?: "").toString()
            is java.net.SocketTimeoutException -> JSONObject()
                .put("error", "TIMEOUT").put("detail", host).toString()
            else -> JSONObject().put("error", "IO").put("detail", "$root").toString()
        }
    }

    /** One request, one connection, and always a JSON string out of it: either
     *  {"status":<code>,"body":"..."} or {"error":<transport code>,"detail":"..."}.
     *
     *  `Connection: close` is deliberate. Keeping a socket alive across the user's accept-or-decline
     *  window would mean a read timeout that has to be minutes long for every chunk request instead
     *  of only for the offer. */
    fun http(
        method: String,
        host: String,
        port: Number,
        path: String,
        json: String,
        token: String,
        pinHex: String,
        body: ByteBuffer?,
        sha: String,
        escape: String,
        timeoutMs: Number
    ): String {
        val payload = bytesOf(body)
        var pinned: Pinned? = null
        return try {
            pinned = openSocket(host, port.toInt(), pinHex)
            val socket = pinned.socket
            socket.soTimeout = timeoutMs.toInt()
            val text = StringBuilder()
                .append("$method $path HTTP/1.1\r\n")
                .append("Host: $host:$port\r\n")
                .append("User-Agent: chuanshu-android\r\n")
                .append("Accept: application/json\r\n")
                .append("Connection: close\r\n")
            if (token.isNotEmpty()) text.append("X-Chuanshu-Auth: $token\r\n")
            if (sha.isNotEmpty()) text.append("X-Sha256: $sha\r\n")
            // Declared by the sender, obeyed by the receiver only when present: a peer whose TLS server
            // hands its scripts the body up to the first 0x00 cannot be given raw bytes at all (spec §4).
            if (escape.isNotEmpty()) text.append("X-Chunk-Escape: $escape\r\n")
            val jsonBytes = if (json.isEmpty()) ByteArray(0) else json.toByteArray(Charsets.UTF_8)
            val length = if (payload.isEmpty()) jsonBytes.size else payload.size
            text.append("Content-Length: $length\r\n\r\n")
            val out = socket.getOutputStream()
            out.write(text.toString().toByteArray(Charsets.US_ASCII))
            writePaced(out, if (payload.isEmpty()) jsonBytes else payload, paceOf(host, port.toInt()).toLong())

            val ins = socket.getInputStream()
            val status = readLine(ins)
            val code = status?.split(" ")?.getOrNull(1)?.toIntOrNull()
            if (code == null) {
                JSONObject().put("error", "PROTOCOL").put("detail", status ?: "对端没答话").toString()
            } else {
                var declared = -1
                while (true) {
                    val line = readLine(ins) ?: break
                    if (line.isEmpty()) break
                    val lower = line.lowercase()
                    if (lower.startsWith("content-length:")) {
                        declared = lower.substring(15).trim().toIntOrNull() ?: -1
                    }
                }
                val raw = if (declared >= 0) readExactly(ins, declared) else readAll(ins)
                val rawText = String(raw, Charsets.UTF_8)
                // The floor is read before the first big body, from the hello this peer just answered.
                if (method == "GET" && path == "/v1/hello") {
                    raisePace(host, port.toInt(), JSONObject(rawText).optInt("chunk_pace_ms", 0))
                }
                if (method == "PUT" && rawText.contains("CHUNK_DIGEST_MISMATCH")) slowPipe(host, port.toInt())
                // `fp` is the leaf digest the handshake actually saw, not what the JSON claims, so the
                // caller can pin the key rather than a number the peer typed about itself.
                JSONObject()
                    .put("status", code)
                    .put("body", rawText)
                    .put("fp", pinned.trust.seen)
                    .toString()
            }
        } catch (e: Throwable) {
            if (method == "PUT") slowPipe(host, port.toInt())
            errorOf(e, host)
        } finally {
            try {
                pinned?.socket?.close()
            } catch (ignored: Throwable) {
            }
        }
    }

    fun digest(buffer: ByteBuffer?): String = hexOf(sha256(bytesOf(buffer)))

    /** An offer's or a file's id: 8 random bytes in hex, the same shape app/net uses (`token_hex(8)`),
     *  because the PC treats these as opaque and the resume map keys on them. */
    fun newId(): String {
        val bytes = ByteArray(8)
        SecureRandom().nextBytes(bytes)
        return hexOf(bytes)
    }

    // -------------------------------------------------------------------- file access

    /** The last thing that went wrong on a read, kept because a `null` slice has to say why: the UTS
     *  half shows this text in the file row instead of a bare "读不出来". */
    private var lastRead: String = ""

    fun readError(): String = lastRead

    /** Android's picker hands back `content://` URIs, not paths, and those only open through the
     *  resolver - every read and stat below branches on this. */
    private fun isContent(path: String): Boolean = path.startsWith("content://")

    private fun resolver(): ContentResolver? = UTSAndroid.getAppContext()?.contentResolver

    /** Bytes at an offset, shorter only at the end of the file. Opened fresh every time: the picker
     *  can hand the same content:// URI back in a later run, and a cached descriptor would then be a
     *  stale view of a file that has since changed. */
    fun readSlice(path: String, offset: Number, length: Number): ByteBuffer? {
        val want = length.toInt()
        val from = offset.toLong()
        if (want <= 0) return ByteBuffer.allocate(0)
        lastRead = ""
        if (!isContent(path)) {
            try {
                val raf = RandomAccessFile(File(path), "r")
                try {
                    raf.seek(from)
                    val out = ByteArray(want)
                    var done = 0
                    while (done < want) {
                        val n = raf.read(out, done, want - done)
                        if (n < 0) break
                        done += n
                    }
                    if (done > 0) return ByteBuffer.wrap(if (done == want) out else out.copyOf(done))
                    lastRead = "读到 0 字节，文件可能已被清理"
                } finally {
                    try {
                        raf.close()
                    } catch (ignored: Throwable) {
                    }
                }
            } catch (e: Throwable) {
                lastRead = "$e"
            }
            return null
        }
        // Android's public RandomAccessFile has no FileDescriptor constructor, so a content:// URI can
        // only come back as a stream - and a provider's stream is free to ignore skip().
        return try {
            val ins = openStream(path) ?: return null
            try {
                skipTo(ins, from)
                val sink = java.io.ByteArrayOutputStream(want)
                val buf = ByteArray(64 * 1024)
                var left = want
                while (left > 0) {
                    val n = ins.read(buf, 0, if (left < buf.size) left else buf.size)
                    if (n < 0) break
                    sink.write(buf, 0, n)
                    left -= n
                }
                ByteBuffer.wrap(sink.toByteArray())
            } finally {
                try {
                    ins.close()
                } catch (ignored: Throwable) {
                }
            }
        } catch (e: Throwable) {
            lastRead = "$e"
            null
        }
    }

    /** Forward, by whatever means the stream grants: skip() first, and when a provider answers 0 - as
     *  it is permitted to, forever - discard through read() instead. Returning on a zero skip would put
     *  the wrong bytes on the wire under a digest that still matches, because the digest is computed
     *  from whatever this read. */
    private fun skipTo(ins: InputStream, from: Long) {
        var left = from
        val buf = ByteArray(64 * 1024)
        while (left > 0) {
            val n = ins.skip(left)
            if (n > 0) {
                left -= n
                continue
            }
            val read = ins.read(buf, 0, if (left < buf.size) left.toInt() else buf.size)
            if (read < 0) throw IOException("文件在偏移 $from 之前就结束了")
            left -= read
        }
    }

    private fun openStream(path: String): InputStream? = try {
        if (isContent(path)) resolver()?.openInputStream(Uri.parse(path))
        else java.io.FileInputStream(File(path))
    } catch (e: Throwable) {
        lastRead = "$e"
        null
    }

    private fun nameOf(path: String): String {
        if (!isContent(path)) return File(path).name
        return try {
            val cursor = resolver()?.query(Uri.parse(path), arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            cursor?.use {
                if (it.moveToFirst() && !it.isNull(0)) it.getString(0) else ""
            } ?: ""
        } catch (e: Throwable) {
            ""
        }
    }

    private fun typeOf(path: String, display: String): String {
        if (isContent(path)) {
            val mine = try {
                resolver()?.getType(Uri.parse(path))
            } catch (e: Throwable) {
                null
            }
            if (mine != null) return mine
        }
        val name = if (display.isNotEmpty()) display else File(path).name
        val dot = name.lastIndexOf('.')
        if (dot < 0 || dot == name.length - 1) return "application/octet-stream"
        val ext = name.substring(dot + 1).lowercase()
        val guess = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
        return if (ext == "md" || ext == "log") "text/plain"
        else if (guess != null) guess else "application/octet-stream"
    }

    /** The offer row for one picked file: its length, the SHA-256 of the whole thing, a modification
     *  time, and a MIME type - or an error to show in its place. */
    fun prepare(path: String): String {
        val display = nameOf(path)
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val ins = openStream(path) ?: return JSONObject()
                .put("error", if (lastRead.isEmpty()) "打不开这个文件" else lastRead).toString()
            var size = 0L
            try {
                val buf = ByteArray(256 * 1024)
                while (true) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                    size += n.toLong()
                }
            } finally {
                try {
                    ins.close()
                } catch (ignored: Throwable) {
                }
            }
            val modified = if (isContent(path)) System.currentTimeMillis() else File(path).lastModified()
            JSONObject()
                .put("size", size)
                .put("sha256", hexOf(digest.digest()))
                .put("mtime", modified / 1000L)
                .put("type", typeOf(path, display))
                .put("name", display)
                .toString()
        } catch (e: Throwable) {
            JSONObject().put("error", "读取失败：$e").toString()
        }
    }

    // -------------------------------------------------------------------- same network

    /** This device's own IPv4 addresses with their prefix lengths, so the page can say whether the
     *  peer it is about to connect to is on the network the phone is actually joined to.
     *
     *  Read from the interfaces rather than guessed from the WiFi manager: the prefix is what makes
     *  a 10/8 site answer honestly instead of assuming a /24 that the IT department never set. */
    fun lan(): String {
        val out = JSONArray()
        try {
            val faces = NetworkInterface.getNetworkInterfaces()
            while (faces.hasMoreElements()) {
                val face = faces.nextElement() ?: continue
                if (!face.isUp || face.isLoopback) continue
                for (address in face.interfaceAddresses) {
                    val ip = address.address
                    if (ip !is Inet4Address) continue
                    out.put(JSONObject()
                        .put("addr", ip.hostAddress ?: "")
                        .put("prefix", address.networkPrefixLength.toInt())
                        .put("iface", face.name ?: ""))
                }
            }
        } catch (e: Throwable) {
            return JSONObject().put("error", "$e").toString()
        }
        return JSONObject().put("addrs", out).toString()
    }
}
