import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// WO-673@v2: operator grants bind one canonical transfer source to its bytes and expiry.
public struct BinaryTransferGrant: Codable {
    public let realpath: String // WO-673@v2: aliases cannot transfer authority to a different file.
    public let sha256: String // WO-673@v2: grants never authorize changed content.
    public let expiresAt: Date // WO-673@v2: every grant has a bounded lifetime.
}

// WO-673@v2: malformed stores expose a fixed warning and contribute no admission authority.
public struct BinaryTransferGrantLoad {
    public let grants: [BinaryTransferGrant] // WO-673@v2: expired grants remain visible to the operator.
    public let warning: String? // WO-673@v2: diagnostic text never includes malformed file contents.
}

// WO-673@v2: policy-independent storage never rewrites the operator's configuration.
public enum BinaryTransferGrants {
    public static let defaultTTL: TimeInterval = 3_600 // WO-673@v2: the operator valve defaults to one hour.
    public static let maximumTTL: TimeInterval = 86_400 // WO-673@v2: grants cannot outlive one day.
    private static let maximumSymlinkTraversals = 40 // WO-673@v2: bound resolution at the usual POSIX symlink limit.

    // WO-673@v2: the existing DEBUG config seam isolates the same user-directory resolver in tests.
    public static var storeURL: URL {
        PastewatchConfig.configPath.deletingLastPathComponent().appendingPathComponent("binary-grants.json")
    }

    // WO-673@v2: resolve aliases even when their policy target has not been created yet.
    public static func canonicalPath(_ path: String) -> String {
        if let resolved = realpath(path, nil) {
            defer { free(resolved) }
            return String(cString: resolved)
        }
        let original = URL(fileURLWithPath: path).path
        var components = Array(original.split(separator: "/").map(String.init))
        var resolved = ""
        var traversals = 0
        while !components.isEmpty {
            let component = components.removeFirst()
            if component == "." { continue }
            if component == ".." { resolved = (resolved as NSString).deletingLastPathComponent; continue }
            let next = resolved + "/" + component
            if let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: next) {
                traversals += 1
                guard traversals <= maximumSymlinkTraversals else { return original }
                if destination.hasPrefix("/") { resolved = "" }
                components = destination.split(separator: "/").map(String.init) + components
            } else { resolved = next }
        }
        return resolved.isEmpty ? "/" : resolved
    }

    // WO-673@v2: validate the entire store before trusting any grant, including a partially malformed array.
    public static func load() -> BinaryTransferGrantLoad {
        guard FileManager.default.fileExists(atPath: storeURL.path) else {
            return BinaryTransferGrantLoad(grants: [], warning: nil)
        }
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let grants = try decoder.decode([BinaryTransferGrant].self,
                                            from: DetectionRules.readBoundedFileData(atPath: storeURL.path))
            guard grants.allSatisfy({ $0.realpath.hasPrefix("/") && $0.sha256.count == 64 &&
                $0.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }) else {
                throw CocoaError(.coderInvalidValue)
            }
            return BinaryTransferGrantLoad(grants: grants, warning: nil)
        } catch {
            return BinaryTransferGrantLoad(grants: [], warning: "Malformed or unreadable binary-grants.json; no grants loaded")
        }
    }

    // WO-673@v2: only a live exact-path exact-content grant admits already-read opaque transfer bytes.
    public static func permitsTransfer(path: String, bytes: Data, now: Date = Date()) -> Bool {
        let canonical = canonicalPath(path)
        let hash = digest(bytes)
        return load().grants.contains { $0.realpath == canonical && $0.sha256 == hash && $0.expiresAt > now }
    }

    // WO-673@v2: duration syntax is explicit and cannot create permanent or overlong grants.
    public static func parseTTL(_ text: String) -> TimeInterval? {
        guard let suffix = text.last, let amount = UInt(text.dropLast()), amount > 0 else { return nil }
        let units: [Character: TimeInterval] = ["s": 1, "m": 60, "h": 3_600]
        guard let unit = units[suffix] else { return nil }
        let ttl = TimeInterval(amount) * unit
        return ttl <= maximumTTL ? ttl : nil
    }

    // WO-673@v2: the operator command records a snapshot, preserving unrelated grants and config bytes.
    public static func record(path: String, ttl: TimeInterval = defaultTTL, now: Date = Date()) throws {
        guard ttl > 0, ttl <= maximumTTL else { throw CocoaError(.coderInvalidValue) }
        let canonical = canonicalPath(path)
        let attributes = try FileManager.default.attributesOfItem(atPath: canonical)
        guard attributes[.type] as? FileAttributeType == .typeRegular else { throw CocoaError(.fileReadUnsupportedScheme) }
        let bytes = try DetectionRules.readBoundedFileData(atPath: canonical)
        let loaded = load()
        guard loaded.warning == nil else { throw CocoaError(.coderInvalidValue) }
        var grants = loaded.grants.filter { $0.realpath != canonical }
        grants.append(BinaryTransferGrant(realpath: canonical, sha256: digest(bytes), expiresAt: now.addingTimeInterval(ttl)))
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        try writeAtomically(encoder.encode(grants))
    }

    // WO-673@v2: the file hash is authority internal to grants, never a diagnostic of checked text.
    private static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    // WO-673@v2: set private permissions before publishing the complete store with an atomic rename.
    private static func writeAtomically(_ bytes: Data) throws {
        let target = storeURL
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        let temporary = target.deletingLastPathComponent().appendingPathComponent(".binary-grants-\(UUID().uuidString)")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer {
            try? handle.close()
            try? FileManager.default.removeItem(at: temporary)
        }
        try handle.write(contentsOf: bytes)
        guard fchmod(descriptor, mode_t(0o600)) == 0, fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard rename(temporary.path, target.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
}
