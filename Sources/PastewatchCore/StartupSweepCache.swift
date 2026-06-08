import Foundation

/// WO-121: JSON cache for warn-once startup sweep behavior.
public final class StartupSweepCache {
    public static let schemaVersion = 1

    private let url: URL
    private let fileManager: FileManager
    private var state: StartupSweepCacheState
    private var loadFailed = false

    public init(url: URL, fileManager: FileManager = .default) {
        self.url = url.standardizedFileURL
        self.fileManager = fileManager
        let loadedState = Self.load(from: self.url, fileManager: fileManager)
        self.state = loadedState ?? StartupSweepCacheState()
        self.loadFailed = loadedState == nil && fileManager.fileExists(atPath: self.url.path)
    }

    public static func defaultURL(homeDirectory: URL) -> URL {
        homeDirectory
            .appendingPathComponent(".pastewatch", isDirectory: true)
            .appendingPathComponent("sweep-cache.json")
    }

    /// WO-121: warn once for each path/hash/finding summary signature.
    public func shouldWarnAndRecord(_ summary: StartupSweepFileSummary) -> Bool {
        let signature = StartupSweepCacheEntry(summary: summary)
        let previous = state.entries[summary.path]
        state.entries[summary.path] = signature

        guard summary.hasFindings else { return false }
        guard !loadFailed else { return true }
        return previous != signature
    }

    public func flush() {
        do {
            let directory = url.deletingLastPathComponent()
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            let data = try JSONEncoder.startupSweep.encode(state)
            try data.write(to: url, options: [.atomic])
        } catch {
            // Cache persistence is best-effort; launch safety must not depend on it.
        }
    }

    private static func load(from url: URL, fileManager: FileManager) -> StartupSweepCacheState? {
        guard fileManager.fileExists(atPath: url.path) else {
            return StartupSweepCacheState()
        }
        do {
            let data = try Data(contentsOf: url)
            let state = try JSONDecoder().decode(StartupSweepCacheState.self, from: data)
            guard state.schemaVersion == schemaVersion else { return StartupSweepCacheState() }
            return state
        } catch {
            return nil
        }
    }
}

struct StartupSweepCacheState: Codable {
    var schemaVersion = StartupSweepCache.schemaVersion
    var entries: [String: StartupSweepCacheEntry] = [:]
}

struct StartupSweepCacheEntry: Codable, Equatable {
    let contentHash: String
    let findingCount: Int
    let severitySummary: [String: Int]

    init(summary: StartupSweepFileSummary) {
        self.contentHash = summary.contentHash
        self.findingCount = summary.findingCount
        self.severitySummary = summary.severityCounts.reduce(into: [:]) { result, pair in
            result[pair.key.rawValue] = pair.value
        }
    }
}

private extension JSONEncoder {
    static var startupSweep: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
