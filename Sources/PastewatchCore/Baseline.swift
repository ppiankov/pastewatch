#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// A single baseline entry — a fingerprint of a known finding.
public struct BaselineEntry: Codable, Equatable {
    public let fingerprint: String
    public let filePath: String

    public init(fingerprint: String, filePath: String) {
        self.fingerprint = fingerprint
        self.filePath = filePath
    }

    /// Create a fingerprint from a match: SHA256(type + ":" + value).
    public static func from(match: DetectedMatch, filePath: String) -> BaselineEntry {
        let input = match.type.rawValue + ":" + match.value
        let digest = SHA256.hash(data: Data(input.utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return BaselineEntry(fingerprint: hex, filePath: filePath)
    }
}

/// A baseline file containing known findings.
public struct BaselineFile: Codable {
    public let version: String
    public let entries: [BaselineEntry]

    public init(version: String = "1", entries: [BaselineEntry]) {
        self.version = version
        self.entries = entries
    }

    /// Load a baseline from a JSON file.
    public static func load(from path: String) throws -> BaselineFile {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(BaselineFile.self, from: data)
    }

    /// Save baseline to a JSON file.
    public func save(to path: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        try data.write(to: URL(fileURLWithPath: path))
    }

    /// Filter out matches that exist in the baseline, returning only new findings.
    public func filterNew(matches: [DetectedMatch], filePath: String) -> [DetectedMatch] {
        let baselineFingerprints = Set(entries.map { $0.fingerprint })
        return matches.filter { match in
            let entry = BaselineEntry.from(match: match, filePath: filePath)
            return !baselineFingerprints.contains(entry.fingerprint)
        }
    }

    /// Filter file scan results, returning only files with new findings.
    public func filterNewResults(results: [FileScanResult]) -> [FileScanResult] {
        let baselineFingerprints = Set(entries.map { $0.fingerprint })
        var filtered: [FileScanResult] = []
        for fr in results {
            let newMatches = fr.matches.filter { match in
                let entry = BaselineEntry.from(match: match, filePath: fr.filePath)
                return !baselineFingerprints.contains(entry.fingerprint)
            }
            if !newMatches.isEmpty {
                filtered.append(FileScanResult(
                    filePath: fr.filePath, matches: newMatches, content: fr.content
                ))
            }
        }
        return filtered
    }
}
