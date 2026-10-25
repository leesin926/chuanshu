package uts.sdk.modules.csTransport

import io.dcloud.uts.UTSAndroid
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Where a receiving phone puts the bytes: `<filesDir>/chuanshu-receive`, which is the same shape as
 *  the desktop's receive directory and just as disposable on uninstall.
 *
 *  The state machine in utssdk/cs-receive.uts has already refused a relpath that tries to escape
 *  (`pathReject`), so the canonical-path check below is the second of the two guards rather than the
 *  only one - a receiver should not have to trust the code that calls it. */
object CsStore {

    private const val ROOT_DIR = "chuanshu-receive"

    private fun root(): File? {
        val dir = UTSAndroid.getAppContext()?.filesDir ?: return null
        val out = File(dir, ROOT_DIR)
        if (!out.exists()) {
            //noinspection BooleanMethodIsAlwaysInverted
            if (!out.mkdirs()) return null
        }
        return out
    }

    private fun cleanPath(base: File, relpath: String): File? {
        if (relpath.isEmpty() || relpath.contains("\u0000")) return null
        return try {
            val candidate = File(base, relpath).canonicalFile
            val inside = candidate.path.startsWith(base.canonicalFile.path + File.separator)
            if (inside) candidate else null
        } catch (e: Throwable) {
            null
        }
    }

    /** A relpath resolves to a writable place, or it does not: '' is the answer the state machine turns
     *  into STORAGE_FULL, which is why nothing here throws at the caller. */
    fun prepare(relpath: String, size: Number): String {
        val base = root() ?: return ""
        val file = cleanPath(base, relpath) ?: return ""
        return try {
            val want = if (size.toLong() < 0) 0L else size.toLong()
            val parent = file.parentFile ?: return ""
            if (!parent.exists() && !parent.mkdirs()) return ""
            if (parent.usableSpace < want) return ""
            val raf = RandomAccessFile(file, "rw")
            try {
                raf.setLength(want)
            } finally {
                raf.close()
            }
            file.absolutePath
        } catch (e: Throwable) {
            ""
        }
    }

    /** '' on success, the reason otherwise. This is a positional write into a file the offer allocated,
     *  so a chunk that lands where it should not is caught by finalize's re-read of the whole file -
     *  the one verdict the contract recognises. */
    fun writeAt(relpath: String, offset: Number, buf: ByteBuffer?): String {
        val base = root() ?: return "拿不到应用私有目录"
        val file = cleanPath(base, relpath) ?: return "这个路径不在接收目录里"
        if (buf == null) return "分块是空的"
        val copy = buf.duplicate()
        copy.rewind()
        val data = ByteArray(copy.remaining())
        copy.get(data)
        return try {
            val raf = RandomAccessFile(file, "rw")
            try {
                val from = offset.toLong()
                if (from < 0) return "偏移是负数"
                // Writing past the end used to be refused. The state machine cannot ask for it: the index
                // is bounded by the manifest's chunk count and the body by that chunk's own length, so
                // `from + size` is at most the declared size - which means the only way to reach this
                // point with a short file is an allocation that is no longer there, and that is the
                // repair #127 needs laid back down, not a wrong offset. A chunk that genuinely sits
                // where it should not still fails, just at finalize's whole-file re-read - the place
                // the contract says the verdict comes from.
                raf.seek(from)
                raf.write(data)
            } finally {
                raf.close()
            }
            ""
        } catch (e: Throwable) {
            "写入失败：$e"
        }
    }

    /** The whole file, read back off the disk. finalize() trusts this and nothing else, which is the
     *  same rule the desktop receiver follows: per-chunk digests say the transfer was consistent, only
     *  a re-read says the file is there. */
    fun digestFile(relpath: String): String {
        val base = root() ?: return ""
        val file = cleanPath(base, relpath) ?: return ""
        if (!file.exists()) return ""
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val ins = java.io.FileInputStream(file)
            try {
                val buf = ByteArray(256 * 1024)
                while (true) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                }
            } finally {
                ins.close()
            }
            val out = StringBuilder()
            for (b in digest.digest()) {
                val v = b.toInt() and 0xff
                out.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 0x0f])
            }
            out.toString()
        } catch (e: Throwable) {
            ""
        }
    }

    /** Whether a file this phone already received is still in the receive root. digestFile() answers
     *  the same question as a side effect of hashing, which is the wrong cost for a card that asks once
     *  a second; and '' there means either "gone" or "unreadable", and the card needs to know which. */
    fun exists(relpath: String): Boolean {
        val base = root() ?: return false
        val file = cleanPath(base, relpath) ?: return false
        return file.exists()
    }

    /** Delete a file a transfer no longer owns, then the directories it leaves behind - an aborted
     *  offer must not stay as a folder full of nothing. */
    fun drop(relpath: String) {
        val base = root() ?: return
        val file = cleanPath(base, relpath) ?: return
        try {
            if (file.exists() && !file.delete()) return
            var parent = file.parentFile
            val stop = base.canonicalFile.path
            while (parent != null && parent.canonicalFile.path != stop) {
                val children = parent.list()
                if (children == null || children.isNotEmpty()) break
                if (!parent.delete()) break
                parent = parent.parentFile
            }
        } catch (e: Throwable) {
        }
    }

    fun freeBytes(): Long = try {
        root()?.usableSpace ?: 0L
    } catch (e: Throwable) {
        0L
    }

    fun rootPath(): String = try {
        root()?.absolutePath ?: ""
    } catch (e: Throwable) {
        ""
    }
}
