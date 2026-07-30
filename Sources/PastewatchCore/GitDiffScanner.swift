import Foundation

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
