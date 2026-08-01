import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// WO-594: exact staged-fixture authorization contains only location and digest evidence.
public struct HookFixtureAuthorization: Codable, Equatable, Sendable {
    public let path: String
    public let line: Int
    public let fingerprint: String

    public init(path: String, line: Int, fingerprint: String) {
        self.path = path
        self.line = line
        self.fingerprint = fingerprint
    }
}

// WO-594: malformed or broadened authorization fails closed without exposing fixture values.
public enum HookFixtureAuthorizationError: LocalizedError {
    case invalidManifest
    case unsupportedVersion
    case tooManyEntries
    case invalidEntry(Int)
    case duplicateLocation(Int)
    case manifestChangedWithAuthorization
    case unreadableFixture
    case missingFixtureLine

    public var errorDescription: String? {
        switch self {
        case .invalidManifest:
            return "invalid hook fixture authorization manifest"
        case .unsupportedVersion:
            return "unsupported hook fixture authorization manifest version"
        case .tooManyEntries:
            return "hook fixture authorization manifest has too many entries"
        case .invalidEntry(let index):
            return "invalid hook fixture authorization entry at index \(index)"
        case .duplicateLocation(let index):
            return "duplicate hook fixture authorization location at index \(index)"
        case .manifestChangedWithAuthorization:
            return "hook fixture authorization manifest must be unchanged in the consuming commit"
        case .unreadableFixture:
            return "fixture file is not readable UTF-8"
        case .missingFixtureLine:
            return "fixture line does not exist"
        }
    }
}

// WO-562@v3: shared helpers used by both GitDiffScanner and GitHistoryScanner.
public enum GitScanHelpers {

    /// Check if a file path should be scanned (extension or dotenv name).
    public static func shouldScanFile(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        let fileName = url.lastPathComponent
        if DotenvClassifier.isDotenvFile(fileName) { return true }
        return DirectoryScanner.allowedExtensions.contains(
            url.pathExtension.lowercased()
        )
    }

    /// Get the effective scan extension (maps dotenv filenames to "env").
    public static func scanExtension(for path: String) -> String {
        let url = URL(fileURLWithPath: path)
        let fileName = url.lastPathComponent
        if DotenvClassifier.isDotenvFile(fileName) { return "env" }
        return url.pathExtension.lowercased()
    }

    /// WO-562@v3: retained compatibility wrapper. Production callers keep trust-policy
    /// filtering explicit at their decision boundary.
    @available(*, deprecated, message: "Apply scan and allowlist policy explicitly at the caller")
    public static func scanAndFilter(
        content: String, ext: String, relativePath: String,
        config: PastewatchConfig
    ) throws -> [DetectedMatch] {
        var matches = try DirectoryScanner.scanFileContentOrThrow(
            content: content, ext: ext,
            relativePath: relativePath, config: config
        )
        matches = Allowlist.filterInlineAllow(matches: matches, content: content)
        matches = Allowlist.fromConfig(config).filter(matches)
        return matches
    }
}

/// Scans git diff output for sensitive data, reporting only findings on added lines.
public struct GitDiffScanner {
    // WO-594: the committed manifest is the only staged-fixture authority.
    public static let hookFixtureManifestPath = ".pastewatch-hook-fixtures.json"

    private static let hookFixtureManifestVersion = 1
    private static let maximumHookFixtureAuthorizations = 1_000

    private struct HookFixtureLocation: Hashable {
        let path: String
        let line: Int
    }

    private struct HookFixtureFilterOutcome {
        let diff: String
        let consumedAuthorizations: Int
    }

    /// Parsed representation of one file in a unified diff.
    struct DiffFile {
        let path: String
        let addedLines: Set<Int>
    }

    /// Mutable state used during diff parsing.
    private struct DiffParserState {
        var files: [DiffFile] = []
        var currentPath: String?
        var currentAdded = Set<Int>()
        var newLineNumber = 0

        mutating func flushCurrentFile() {
            if let path = currentPath, !currentAdded.isEmpty {
                files.append(DiffFile(path: path, addedLines: currentAdded))
            }
        }
    }

    // WO-599@v2: Git diff scans enforce bounded subprocess and file inputs.
    /// Scan staged and/or unstaged git changes for secrets.
    public static func scan(
        staged: Bool = true,
        unstaged: Bool = false,
        config: PastewatchConfig,
        bail: Bool = false,
        limits: ScanInputLimits = .current()
    ) throws -> [FileScanResult] {
        let diffFiles = try collectDiffFiles(
            staged: staged,
            unstaged: unstaged,
            limits: limits
        )

        guard !diffFiles.isEmpty else { return [] }

        var results: [FileScanResult] = []

        for df in diffFiles {
            // WO-562@v3: shared extension classification.
            guard GitScanHelpers.shouldScanFile(df.path) else {
                continue
            }

            // Get file content
            let content: String
            if staged && !unstaged {
                // Staged only: get from git index
                do {
                    content = try runGit(["show", ":\(df.path)"], limits: limits)
                } catch let error as ScanInputLimitError {
                    // WO-599@v2: a bounded staged blob is an operational failure, not a skipped file.
                    throw error
                } catch let error as ScanInputTextError {
                    // WO-602@v2: malformed staged text cannot be reported as absent.
                    throw error
                } catch {
                    continue
                }
            } else {
                // Unstaged or both: read from disk
                let data: Data
                do {
                    data = try DetectionRules.readBoundedFileData(
                        atPath: df.path,
                        limits: limits
                    )
                } catch let error as ScanInputLimitError {
                    // WO-599@v2: working-tree races cannot turn limit failures into clean scans.
                    throw error
                } catch {
                    continue
                }
                // WO-602@v2: malformed supported working-tree text fails the scan.
                guard let disk = String(data: data, encoding: .utf8) else {
                    throw ScanInputTextError.invalidUTF8
                }
                content = disk
            }

            guard !content.isEmpty else { continue }

            // WO-562@v3: share classification only; trust-policy filtering remains
            // explicit at this caller.
            var fileMatches = try DirectoryScanner.scanFileContentOrThrow(
                content: content,
                ext: GitScanHelpers.scanExtension(for: df.path),
                relativePath: df.path,
                config: config,
                limits: limits
            )
            fileMatches = Allowlist.filterInlineAllow(matches: fileMatches, content: content)
            fileMatches = Allowlist.fromConfig(config).filter(fileMatches)

            // Filter to only added lines
            fileMatches = fileMatches.filter { df.addedLines.contains($0.line) }

            if !fileMatches.isEmpty {
                results.append(FileScanResult(
                    filePath: df.path,
                    matches: fileMatches,
                    content: content
                ))
                if bail { return results }
            }
        }

        return results.sorted { $0.filePath < $1.filePath }
    }

    // WO-594: produce reviewable authorization evidence without returning fixture text.
    public static func hookFixtureAuthorization(
        filePath: String,
        line: Int,
        limits: ScanInputLimits = .current()
    ) throws -> HookFixtureAuthorization {
        let normalizedPath = try validateHookFixturePath(filePath)
        guard line > 0 else {
            throw HookFixtureAuthorizationError.missingFixtureLine
        }

        let data = try DetectionRules.readBoundedFileData(
            atPath: normalizedPath,
            limits: limits
        )
        guard let content = String(data: data, encoding: .utf8) else {
            throw HookFixtureAuthorizationError.unreadableFixture
        }
        let lines = content.components(separatedBy: "\n")
        guard line <= lines.count else {
            throw HookFixtureAuthorizationError.missingFixtureLine
        }
        let fixtureLine = normalizedHookFixtureLine(lines[line - 1])
        return HookFixtureAuthorization(
            path: normalizedPath,
            line: line,
            fingerprint: hookFixtureFingerprint(fixtureLine)
        )
    }

    // WO-594: SHA-256 binds authorization to the complete source line.
    public static func hookFixtureFingerprint(_ line: String) -> String {
        SHA256.hash(data: Data(line.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    // WO-594: filter only exact committed path/line/digest matches from staged diff input.
    public static func filteredHookStagedDiff(
        limits: ScanInputLimits = .current()
    ) throws -> String {
        // WO-615/WO-616: read raw staged bytes and expand moves at their destination.
        let diff = try runGit(
            [
                "diff", "--cached", "--diff-filter=d", "--no-color", "--unified=0",
                "--no-ext-diff", "--no-textconv", "--no-renames"
            ],
            limits: limits
        )
        let authorizations = try committedHookFixtureAuthorizations(limits: limits)
        let outcome = try filterAuthorizedHookFixturesWithOutcome(
            in: diff,
            authorizations: authorizations
        )
        if outcome.consumedAuthorizations > 0 {
            // WO-609: authority consumed by this commit must remain in its resulting tree.
            let manifestChanges = try runGit(
                [
                    "diff", "--cached", "--name-only",
                    "--no-ext-diff", "--no-textconv", "--no-renames", "--",
                    hookFixtureManifestPath
                ],
                limits: limits
            )
            guard manifestChanges.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw HookFixtureAuthorizationError.manifestChangedWithAuthorization
            }
        }
        return outcome.diff
    }

    // WO-594: public pure transform keeps authorization edge cases deterministic in tests.
    public static func filterAuthorizedHookFixtures(
        in diff: String,
        authorizations: [HookFixtureAuthorization]
    ) throws -> String {
        try filterAuthorizedHookFixturesWithOutcome(
            in: diff,
            authorizations: authorizations
        ).diff
    }

    // WO-608: explicit hunk state prevents source text from impersonating diff metadata.
    private static func filterAuthorizedHookFixturesWithOutcome(
        in diff: String,
        authorizations: [HookFixtureAuthorization]
    ) throws -> HookFixtureFilterOutcome {
        var authorizedByLocation: [HookFixtureLocation: String] = [:]
        for (index, authorization) in authorizations.enumerated() {
            let path = try validateHookFixturePath(authorization.path)
            guard authorization.line > 0,
                  isValidHookFixtureFingerprint(authorization.fingerprint) else {
                throw HookFixtureAuthorizationError.invalidEntry(index)
            }
            let location = HookFixtureLocation(path: path, line: authorization.line)
            guard authorizedByLocation[location] == nil else {
                throw HookFixtureAuthorizationError.duplicateLocation(index)
            }
            authorizedByLocation[location] = authorization.fingerprint
        }

        var currentPath: String?
        var currentLine: Int?
        var filtered: [String] = []
        var consumedAuthorizations = 0

        for diffLine in diff.components(separatedBy: "\n") {
            if diffLine.hasPrefix("diff --git ") {
                currentPath = nil
                currentLine = nil
            } else if diffLine.hasPrefix("@@ ") {
                currentLine = parseHunkHeader(diffLine)
            } else if currentLine != nil, diffLine.hasPrefix("+") {
                // WO-606: fingerprint generation and staged verification share CRLF handling.
                let sourceLine = normalizedHookFixtureLine(String(diffLine.dropFirst()))
                if let path = currentPath,
                   let line = currentLine,
                   authorizedByLocation[HookFixtureLocation(path: path, line: line)]
                    == hookFixtureFingerprint(sourceLine) {
                    filtered.append("+")
                    consumedAuthorizations += 1
                } else {
                    filtered.append(diffLine)
                }
                if let line = currentLine {
                    currentLine = line + 1
                }
                continue
            } else if currentLine != nil, diffLine.hasPrefix("-") {
                filtered.append(diffLine)
                continue
            } else if currentLine != nil,
                      diffLine.hasPrefix(" ") || diffLine.isEmpty {
                currentLine? += 1
            } else if currentLine == nil, diffLine.hasPrefix("+++ ") {
                currentPath = extractPath(from: diffLine)
            }
            filtered.append(diffLine)
        }
        return HookFixtureFilterOutcome(
            diff: filtered.joined(separator: "\n"),
            consumedAuthorizations: consumedAuthorizations
        )
    }

    // WO-594: staged manifest edits are deliberately ignored until separately committed.
    static func committedHookFixtureAuthorizations(
        limits: ScanInputLimits = .current()
    ) throws -> [HookFixtureAuthorization] {
        let manifest: String
        do {
            manifest = try runGit(
                ["show", "HEAD:\(hookFixtureManifestPath)"],
                limits: limits
            )
        } catch let error as ScanInputLimitError {
            throw error
        } catch let error as ScanInputTextError {
            throw error
        } catch {
            return []
        }
        return try parseHookFixtureManifest(Data(manifest.utf8))
    }

    private static func parseHookFixtureManifest(
        _ data: Data
    ) throws -> [HookFixtureAuthorization] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == ["version", "fixtures"],
              let versionNumber = root["version"] as? NSNumber,
              let version = exactJSONInteger(versionNumber),
              let entries = root["fixtures"] as? [Any] else {
            throw HookFixtureAuthorizationError.invalidManifest
        }
        guard version == hookFixtureManifestVersion else {
            throw HookFixtureAuthorizationError.unsupportedVersion
        }
        guard entries.count <= maximumHookFixtureAuthorizations else {
            throw HookFixtureAuthorizationError.tooManyEntries
        }

        var authorizations: [HookFixtureAuthorization] = []
        var locations = Set<HookFixtureLocation>()
        for (index, value) in entries.enumerated() {
            guard let entry = value as? [String: Any],
                  Set(entry.keys) == ["path", "line", "fingerprint"],
                  let pathValue = entry["path"] as? String,
                  let lineValue = entry["line"] as? NSNumber,
                  let line = exactJSONInteger(lineValue),
                  let fingerprint = entry["fingerprint"] as? String else {
                throw HookFixtureAuthorizationError.invalidEntry(index)
            }
            let path = try validateHookFixturePath(pathValue)
            guard line > 0, isValidHookFixtureFingerprint(fingerprint) else {
                throw HookFixtureAuthorizationError.invalidEntry(index)
            }
            let location = HookFixtureLocation(path: path, line: line)
            guard locations.insert(location).inserted else {
                throw HookFixtureAuthorizationError.duplicateLocation(index)
            }
            authorizations.append(
                HookFixtureAuthorization(
                    path: path,
                    line: line,
                    fingerprint: fingerprint
                )
            )
        }
        // WO-610@v2: reject parser-ambiguous duplicate or escaped schema keys.
        guard hasExactHookManifestKeyMultiplicity(data, entryCount: entries.count) else {
            throw HookFixtureAuthorizationError.invalidManifest
        }
        return authorizations
    }

    // WO-610@v2: Foundation collapses duplicate keys, so validate key tokens first.
    private static func hasExactHookManifestKeyMultiplicity(
        _ data: Data,
        entryCount: Int
    ) -> Bool {
        let bytes = [UInt8](data)
        var index = 0
        var counts = [
            "version": 0,
            "fixtures": 0,
            "path": 0,
            "line": 0,
            "fingerprint": 0
        ]

        while index < bytes.count {
            guard bytes[index] == 0x22 else {
                index += 1
                continue
            }
            index += 1
            var token: [UInt8] = []
            var escaped = false
            while index < bytes.count, bytes[index] != 0x22 {
                if bytes[index] == 0x5C {
                    escaped = true
                    index += 2
                } else {
                    token.append(bytes[index])
                    index += 1
                }
            }
            guard index < bytes.count else { return false }
            index += 1

            var lookahead = index
            while lookahead < bytes.count,
                  [0x20, 0x09, 0x0A, 0x0D].contains(bytes[lookahead]) {
                lookahead += 1
            }
            guard lookahead < bytes.count, bytes[lookahead] == 0x3A else {
                continue
            }
            guard !escaped,
                  let key = String(bytes: token, encoding: .utf8) else {
                return false
            }
            counts[key, default: 0] += 1
        }

        return counts == [
            "version": 1,
            "fixtures": 1,
            "path": entryCount,
            "line": entryCount,
            "fingerprint": entryCount
        ]
    }

    // WO-605: authorization metadata accepts JSON integer storage only, never truncation.
    private static func exactJSONInteger(_ number: NSNumber) -> Int? {
        let type = String(cString: number.objCType)
        guard ["s", "i", "l", "q"].contains(type) else {
            return nil
        }
        return Int(exactly: number.int64Value)
    }

    // WO-606: CR is a line terminator artifact, not part of the authorized source line.
    private static func normalizedHookFixtureLine(_ line: String) -> String {
        line.hasSuffix("\r") ? String(line.dropLast()) : line
    }

    private static func validateHookFixturePath(_ path: String) throws -> String {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.contains("\\"),
              !parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else {
            throw HookFixtureAuthorizationError.invalidManifest
        }
        return parts.joined(separator: "/")
    }

    private static func isValidHookFixtureFingerprint(_ fingerprint: String) -> Bool {
        fingerprint.count == 64
            && fingerprint.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    // WO-599@v2: collect bounded Git output without inflating scan control flow.
    private static func collectDiffFiles(
        staged: Bool,
        unstaged: Bool,
        limits: ScanInputLimits
    ) throws -> [DiffFile] {
        var diffFiles: [DiffFile] = []
        if staged {
            let diff = try runGit(
                ["diff", "--cached", "--no-color", "--diff-filter=d"],
                limits: limits
            )
            diffFiles.append(contentsOf: parseDiff(diff))
        }
        guard unstaged else { return diffFiles }

        let diff = try runGit(
            ["diff", "--no-color", "--diff-filter=d"],
            limits: limits
        )
        for unstagedFile in parseDiff(diff) {
            if let index = diffFiles.firstIndex(where: { $0.path == unstagedFile.path }) {
                diffFiles[index] = DiffFile(
                    path: unstagedFile.path,
                    addedLines: diffFiles[index].addedLines.union(unstagedFile.addedLines)
                )
            } else {
                diffFiles.append(unstagedFile)
            }
        }
        return diffFiles
    }

    // MARK: - Diff parsing

    /// Parse unified diff output into per-file entries with added line numbers.
    static func parseDiff(_ diff: String) -> [DiffFile] {
        guard !diff.isEmpty else { return [] }

        var state = DiffParserState()
        let lines = diff.components(separatedBy: "\n")

        for line in lines {
            parseDiffLine(line, state: &state)
        }

        // Save last file
        state.flushCurrentFile()
        return state.files
    }

    private static func parseDiffLine(_ line: String, state: inout DiffParserState) {
        if line.hasPrefix("diff --git ") {
            state.flushCurrentFile()
            state.currentPath = nil
            state.currentAdded = Set<Int>()
            state.newLineNumber = 0
            return
        }

        if line.hasPrefix("Binary files ") {
            state.currentPath = nil
            return
        }

        if line.hasPrefix("+++ ") {
            state.currentPath = extractPath(from: line)
            return
        }

        if line.hasPrefix("--- ") { return }

        if line.hasPrefix("@@ ") {
            if let newStart = parseHunkHeader(line) {
                state.newLineNumber = newStart
            }
            return
        }

        guard state.currentPath != nil else { return }

        if line.hasPrefix("+") {
            state.currentAdded.insert(state.newLineNumber)
            state.newLineNumber += 1
        } else if line.hasPrefix("-") {
            // Removed line: don't increment new-file counter
        } else if line.hasPrefix(" ") || line.isEmpty {
            state.newLineNumber += 1
        }
    }

    private static func extractPath(from line: String) -> String? {
        let pathPart = String(line.dropFirst(4))
        if pathPart == "/dev/null" { return nil }
        if pathPart.hasPrefix("b/") { return String(pathPart.dropFirst(2)) }
        return pathPart
    }

    /// Extract the new-file start line from a hunk header like `@@ -1,3 +4,5 @@`.
    private static func parseHunkHeader(_ line: String) -> Int? {
        // Match +start or +start,count
        guard let plusRange = line.range(of: "+", range: line.index(line.startIndex, offsetBy: 3)..<line.endIndex) else {
            return nil
        }
        let afterPlus = line[plusRange.upperBound...]
        // Find end: either comma or space
        let endIdx = afterPlus.firstIndex(where: { $0 == "," || $0 == " " }) ?? afterPlus.endIndex
        return Int(afterPlus[..<endIdx])
    }

    // MARK: - Git subprocess

    /// Run a git command and return stdout. Throws on non-zero exit.
    static func runGit(
        _ arguments: [String],
        limits: ScanInputLimits = .current()
    ) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        try process.run()

        let data: Data
        do {
            // WO-599@v2: drain while git runs and cap stdout before it can fill the pipe.
            data = try DetectionRules.readBoundedInputData(
                from: pipe.fileHandleForReading,
                limits: limits
            )
        } catch {
            if process.isRunning {
                process.terminate()
            }
            process.waitUntilExit()
            throw error
        }
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw GitDiffError.gitCommandFailed(arguments.joined(separator: " "))
        }

        // WO-602@v2: malformed Git output must not collapse into a clean empty scan.
        guard let output = String(data: data, encoding: .utf8) else {
            throw ScanInputTextError.invalidUTF8
        }
        return output
    }
}

/// Errors from git diff scanning.
public enum GitDiffError: Error, CustomStringConvertible {
    case gitCommandFailed(String)
    case notAGitRepository

    public var description: String {
        switch self {
        case .gitCommandFailed(let cmd):
            return "git command failed: git \(cmd)"
        case .notAGitRepository:
            return "not a git repository"
        }
    }
}
