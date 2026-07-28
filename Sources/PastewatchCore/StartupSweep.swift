import Foundation

/// WO-121: pre-launch sweep for credential candidates in shell startup files.
public struct StartupSweep {
    public static let maxFileSizeBytes: Int64 = 1_048_576

    private static let shellStartupRelativePaths = [
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".config/fish/config.fish",
    ]

    private let fileManager: FileManager
    private let homeDirectory: URL
    private let currentDirectory: URL
    private let config: PastewatchConfig

    public init(
        homeDirectory: URL,
        currentDirectory: URL,
        config: PastewatchConfig = .defaultConfig,
        fileManager: FileManager = .default
    ) {
        self.homeDirectory = homeDirectory.standardizedFileURL
        self.currentDirectory = currentDirectory.standardizedFileURL
        self.config = config
        self.fileManager = fileManager
    }

    /// WO-121: deterministic candidate expansion with injectable home/cwd for fixture-only tests.
    public func candidatePaths() -> [URL] {
        var candidates = Self.shellStartupRelativePaths.map {
            homeDirectory.appendingPathComponent($0)
        }

        candidates.append(contentsOf: fishConfDPaths())
        candidates.append(contentsOf: envrcPaths())

        var seen = Set<String>()
        return candidates.compactMap { url in
            let normalized = Self.normalizedPath(for: url)
            guard seen.insert(normalized).inserted else { return nil }
            return URL(fileURLWithPath: normalized)
        }
    }

    /// WO-121: scan startup candidates without exposing source values.
    public func run(cache: StartupSweepCache? = nil) -> StartupSweepReport {
        let candidates = candidatePaths()
        var warnedFiles: [StartupSweepFileSummary] = []
        var suppressedFiles: [StartupSweepFileSummary] = []
        var cleanFiles: [StartupSweepFileSummary] = []
        var skippedFiles: [StartupSweepSkippedFile] = []
        var readErrors: [StartupSweepReadError] = []
        var sharedPatternErrors: [StartupSweepSharedPatternWarning] = []

        for candidate in candidates {
            let normalizedPath = Self.normalizedPath(for: candidate)
            guard fileManager.fileExists(atPath: normalizedPath) else { continue }

            do {
                let byteCount = try fileSize(atPath: normalizedPath)
                guard byteCount <= Self.maxFileSizeBytes else {
                    skippedFiles.append(
                        StartupSweepSkippedFile(path: normalizedPath, byteCount: byteCount, reason: "file exceeds startup sweep size limit")
                    )
                    continue
                }

                let content = try String(contentsOfFile: normalizedPath, encoding: .utf8)
                // WO-578@v2: startup files use the same format-aware scanner and trusted-file
                // policy as other operator-controlled file surfaces.
                let scannedMatches = try DirectoryScanner.scanFileContentOrThrow(
                    content: content,
                    ext: Self.scanExtension(for: candidate),
                    relativePath: normalizedPath,
                    config: config
                )
                let matches = GuardDecision.evaluate(
                    matches: scannedMatches,
                    content: content,
                    config: config,
                    contentTrust: .trustedFile,
                    minimumSeverity: nil
                ).reportableMatches
                let summary = StartupSweepFileSummary(
                    path: normalizedPath,
                    contentHash: Self.contentHash(for: content),
                    findingCount: matches.count,
                    severityCounts: Self.severityCounts(for: matches),
                    lineNumbers: Self.lineNumbers(for: matches),
                    findingIdentityHash: Self.findingIdentityHash(
                        for: matches,
                        in: content
                    )
                )

                if !summary.hasFindings {
                    _ = cache?.shouldWarnAndRecord(summary)
                    cleanFiles.append(summary)
                } else if cache?.shouldWarnAndRecord(summary) ?? true {
                    warnedFiles.append(summary)
                } else {
                    // WO-590@v2: warn-once suppression is not evidence that a file is clean.
                    suppressedFiles.append(summary)
                }
            } catch let error as SharedSecretPatternLoadError {
                // WO-578@v2: configuration errors are reported without creating a clean cache entry.
                sharedPatternErrors.append(
                    StartupSweepSharedPatternWarning(
                        path: normalizedPath,
                        messages: [Self.sanitizedErrorMessage(error)]
                    )
                )
            } catch {
                // WO-578@v2: read and structured-scan failures stay out of the clean cache.
                readErrors.append(
                    StartupSweepReadError(path: normalizedPath, message: Self.sanitizedErrorMessage(error))
                )
            }
        }

        cache?.flush()

        return StartupSweepReport(
            warnedFiles: warnedFiles,
            suppressedFiles: suppressedFiles,
            cleanFiles: cleanFiles,
            skippedFiles: skippedFiles,
            readErrors: readErrors,
            sharedPatternErrors: sharedPatternErrors
        )
    }

    private func fishConfDPaths() -> [URL] {
        let directory = homeDirectory.appendingPathComponent(".config/fish/conf.d")
        guard fileManager.fileExists(atPath: directory.path) else { return [] }
        guard let urls = try? fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }
        return urls
            .filter { $0.pathExtension == "fish" }
            .sorted { Self.normalizedPath(for: $0) < Self.normalizedPath(for: $1) }
    }

    private func envrcPaths() -> [URL] {
        let homePath = Self.normalizedPath(for: homeDirectory)
        var currentPath = Self.normalizedPath(for: currentDirectory)
        guard currentPath == homePath || currentPath.hasPrefix(homePath + "/") else { return [] }

        var urls: [URL] = []
        while currentPath.count >= homePath.count {
            urls.append(URL(fileURLWithPath: currentPath).appendingPathComponent(".envrc"))
            if currentPath == homePath { break }
            let parent = URL(fileURLWithPath: currentPath).deletingLastPathComponent().path
            guard parent != currentPath else { break }
            currentPath = parent
        }
        return urls
    }

    private func fileSize(atPath path: String) throws -> Int64 {
        let attributes = try fileManager.attributesOfItem(atPath: path)
        if let size = attributes[.size] as? NSNumber {
            return size.int64Value
        }
        return 0
    }

    // WO-578@v2: .envrc is dotenv-shaped even though Foundation reports no extension.
    private static func scanExtension(for url: URL) -> String {
        let fileName = url.lastPathComponent
        if fileName == ".envrc" || DotenvClassifier.isDotenvFile(fileName) {
            return "env"
        }
        return url.pathExtension.lowercased()
    }

    public static func normalizedPath(for url: URL) -> String {
        url.standardizedFileURL.path
    }

    static func contentHash(for content: String) -> String {
        let fnvOffsetBasis: UInt64 = 14_695_981_039_346_656_037
        let fnvPrime: UInt64 = 1_099_511_628_211
        var hash = fnvOffsetBasis
        for byte in content.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* fnvPrime
        }
        return "fnv1a64:" + String(hash, radix: 16)
    }

    private static func severityCounts(for matches: [DetectedMatch]) -> [Severity: Int] {
        matches.reduce(into: [:]) { counts, match in
            counts[match.effectiveSeverity, default: 0] += 1
        }
    }

    private static func lineNumbers(for matches: [DetectedMatch]) -> [Int] {
        Array(Set(matches.map(\.line))).sorted()
    }

    // WO-590@v2: hash only non-secret evidence needed to distinguish finding sets.
    private static func findingIdentityHash(
        for matches: [DetectedMatch],
        in content: String
    ) -> String {
        let metadata = matches.map { match -> String in
            let range = NSRange(match.range, in: content)
            return [
                match.type.rawValue,
                match.effectiveSeverity.rawValue,
                String(match.line),
                String(range.location),
                String(range.length),
                match.customRuleName ?? ""
            ].joined(separator: "\u{1F}")
        }.sorted().joined(separator: "\u{1E}")
        return contentHash(for: metadata)
    }

    private static func sanitizedErrorMessage(_ error: Error) -> String {
        String(describing: type(of: error))
    }
}

/// WO-121: sanitized startup sweep result for launch warning rendering.
public struct StartupSweepReport {
    public let warnedFiles: [StartupSweepFileSummary]
    public let suppressedFiles: [StartupSweepFileSummary] // WO-590@v2: findings already warned.
    public let cleanFiles: [StartupSweepFileSummary]
    public let skippedFiles: [StartupSweepSkippedFile]
    public let readErrors: [StartupSweepReadError]
    public let sharedPatternErrors: [StartupSweepSharedPatternWarning]

    public var hasWarningOutput: Bool {
        !warnedFiles.isEmpty || !skippedFiles.isEmpty || !readErrors.isEmpty || !sharedPatternErrors.isEmpty
    }
}

/// WO-121: per-file finding summary without captured credential values.
public struct StartupSweepFileSummary: Equatable {
    public let path: String
    public let contentHash: String
    public let findingCount: Int
    public let severityCounts: [Severity: Int]
    public let lineNumbers: [Int]
    public let findingIdentityHash: String // WO-590@v2: value-free cache identity.

    public var hasFindings: Bool {
        findingCount > 0
    }
}

/// WO-121: oversized-file skip summary without file contents.
public struct StartupSweepSkippedFile: Equatable {
    public let path: String
    public let byteCount: Int64
    public let reason: String
}

/// WO-121, WO-578@v2: non-secret read or scan error summary.
public struct StartupSweepReadError: Equatable {
    public let path: String
    public let message: String
}

/// WO-121: shared-pattern diagnostics surfaced without file contents.
public struct StartupSweepSharedPatternWarning: Equatable {
    public let path: String
    public let messages: [String]
}

/// WO-121: single aggregated warning block for launch stderr.
public enum StartupSweepWarningRenderer {
    public static func render(_ report: StartupSweepReport) -> String? {
        guard report.hasWarningOutput else { return nil }

        var lines = [
            "pastewatch: startup sweep found pre-existing credential risk:",
        ]

        for file in report.warnedFiles {
            let severities = severitySummary(file.severityCounts)
            let lineList = file.lineNumbers.map(String.init).joined(separator: ",")
            lines.append("- \(file.path): \(file.findingCount) finding(s), severities: \(severities), lines: \(lineList)")
        }

        for skipped in report.skippedFiles {
            lines.append("- \(skipped.path): skipped (\(skipped.reason), \(skipped.byteCount) bytes)")
        }

        for readError in report.readErrors {
            // WO-578@v2: this bucket also contains fail-closed structured-scan errors.
            lines.append("- \(readError.path): skipped (scan error: \(readError.message))")
        }

        for warning in report.sharedPatternErrors {
            lines.append("- \(warning.path): shared pattern warning(s): \(warning.messages.count)")
        }

        lines.append("pastewatch: launch continues; rotate or remove persisted credentials separately.")
        return lines.joined(separator: "\n") + "\n"
    }

    private static func severitySummary(_ counts: [Severity: Int]) -> String {
        Severity.allCases
            .filter { counts[$0, default: 0] > 0 }
            .map { "\($0.rawValue)=\(counts[$0, default: 0])" }
            .joined(separator: ",")
    }
}
