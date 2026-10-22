import Foundation

/** Where a receiving iPhone puts the bytes, and what it can say about them afterwards.
 *
 *  The state machine in `../cs-receive.uts` has already refused a relpath that tries to escape
 *  (`pathReject`), so the resolved-path check below is the second of the two guards rather than the
 *  only one - a receiver should not have to trust the code that calls it. iOS adds a reason to keep it:
 *  the receive directory is reachable through a URL, and a URL is easy to build out of somebody else's
 *  string.
 *
 *  The `FileHandle` calls here are the old, non-throwing ones (`seek(toFileOffset:)`,
 *  `truncate(atOffset:)`) rather than the iOS 13.4 replacements they were deprecated by. This plugin
 *  carries the floor CryptoKit sets - 13.0 - and an availability error stops a build where a
 *  deprecation warning does not. */
public enum CsStore {

    /** '' when the relpath does not resolve to a writable place inside the receive directory. The state
     *  machine turns that into STORAGE_FULL, so nothing here throws at the caller. */
    public static func prepare(_ relpath: String, _ size: NSNumber) -> String {
        guard let base = CsPaths.receiveDir(), let file = inside(base, relpath) else { return "" }
        let want = Int64(truncating: size)
        let room = freeBytes()
        if want > 0 && room > 0 && want > room { return "" }
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            if !fm.fileExists(atPath: file.path) {
                fm.createFile(atPath: file.path, contents: Data(), attributes: nil)
            }
        } catch {
            return ""
        }
        guard let handle = FileHandle(forUpdating: file) else { return "" }
        handle.truncate(atOffset: UInt64(want < 0 ? 0 : want))
        handle.closeFile()
        return file.path
    }

    /// '' on success, the reason otherwise. A chunk that lands at the wrong offset has to fail loudly:
    /// the sender's per-chunk digest would still match whatever we stored.
    public static func writeAt(_ relpath: String, _ offset: NSNumber, _ data: Data) -> String {
        guard let base = CsPaths.receiveDir() else { return "拿不到应用私有目录" }
        guard let file = inside(base, relpath) else { return "这个路径不在接收目录里" }
        if data.isEmpty { return "分块是空的" }
        let from = Int64(truncating: offset)
        if from < 0 { return "偏移是负数" }
        let length = fileSize(file)
        if from + Int64(data.count) > length { return "写入超出文件末尾" }
        guard let handle = FileHandle(forUpdating: file) else { return "打不开这个文件" }
        defer { handle.closeFile() }
        handle.seek(toFileOffset: UInt64(from))
        handle.write(data)
        return ""
    }

    /// The whole file, read back off the disk. finalize() trusts this and nothing else, which is the
    /// same rule the desktop receiver follows: per-chunk digests say the transfer was consistent, only
    /// a re-read says the file is there.
    public static func digestFile(_ relpath: String) -> String {
        guard let base = CsPaths.receiveDir(), let file = inside(base, relpath) else { return "" }
        guard let handle = FileHandle(forReadingAtPath: file.path) else { return "" }
        defer { handle.closeFile() }
        var hasher = SHA256Stream()
        while true {
            let block = handle.readData(ofLength: 256 * 1024)
            if block.isEmpty { break }
            hasher.update(block)
        }
        return CsBytes.hex(hasher.final())
    }

    /// Delete a file a transfer no longer owns, then the directories it leaves behind - an aborted
    /// offer must not stay as a folder full of nothing.
    public static func drop(_ relpath: String) {
        guard let base = CsPaths.receiveDir(), let file = inside(base, relpath) else { return }
        let fm = FileManager.default
        guard fm.fileExists(atPath: file.path) else { return }
        do { try fm.removeItem(at: file) } catch { return }
        var parent = file.deletingLastPathComponent()
        let stop = base.standardizedFileURL.path
        while parent.standardizedFileURL.path != stop {
            let children = (try? fm.contentsOfDirectory(atPath: parent.path)) ?? []
            if !children.isEmpty { break }
            do { try fm.removeItem(at: parent) } catch { break }
            parent = parent.deletingLastPathComponent()
        }
    }

    public static func freeBytes() -> Int64 {
        guard let url = CsPaths.receiveDir() else { return 0 }
        let values = try? url.resourceValues(forKeys: [.volumeAvailableCapacityKey])
        return Int64(values?.volumeAvailableCapacity ?? 0)
    }

    public static func rootPath() -> String {
        return CsPaths.receiveDir()?.path ?? ""
    }

    private static func fileSize(_ file: URL) -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(atPath: file.path)
        return (attrs?[.size] as? Int64) ?? 0
    }

    /// The relpath resolved inside `base`, or nil if it escapes it. Both the traversal check and the
    /// symlink question are answered by standardising the resolved URL against the directory it is
    /// supposed to stay in.
    private static func inside(_ base: URL, _ relpath: String) -> URL? {
        if relpath.isEmpty || relpath.contains("\u{0000}") { return nil }
        let candidate = base.standardizedFileURL
            .appendingPathComponent(relpath)
            .standardizedFileURL
        let root = base.standardizedFileURL.path
        guard candidate.path.hasPrefix(root + "/") else { return nil }
        return candidate
    }
}

/** SHA-256 over a file too big to hold in memory, in the pieces the platform already gives us.
 *
 *  CryptoKit's one-shot `hash(data:)` would mean reading a received multi-gigabyte file into RAM to
 *  check it, which is the one thing a receiver must not do to itself. `finalize()` runs on a local copy
 *  of the hasher because it consumes it, and the caller keeps this struct alive while doing so. */
struct SHA256Stream {
    private var hasher = SHA256.Hasher()

    mutating func update(_ data: Data) {
        hasher.update(data: data)
    }

    mutating func final() -> Data {
        var closing = hasher
        return Data(closing.finalize())
    }
}
