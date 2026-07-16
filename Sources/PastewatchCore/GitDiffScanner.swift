import Foundation

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

    /// Scan staged and/or unstaged git changes for secrets.
    public static func scan(
        staged: Bool = true,
        unstaged: Bool = false,
        config: PastewatchConfig,
        bail: Bool = false
    ) throws -> [FileScanResult] {
        var diffFiles: [DiffFile] = []

        if staged {
            let diff = try runGit(["diff", "--cached", "--no-color", "--diff-filter=d"])
            diffFiles.append(contentsOf: parseDiff(diff))
        }

        if unstaged {
            let diff = try runGit(["diff", "--no-color", "--diff-filter=d"])
            let unstagedFiles = parseDiff(diff)
            // Merge unstaged into existing: union addedLines for same path
            for uf in unstagedFiles {
                if let idx = diffFiles.firstIndex(where: { $0.path == uf.path }) {
                    let merged = DiffFile(
                        path: uf.path,
                        addedLines: diffFiles[idx].addedLines.union(uf.addedLines)
                    )
                    diffFiles[idx] = merged
                } else {
                    diffFiles.append(uf)
                }
            }
        }

        guard !diffFiles.isEmpty else { return [] }

        var results: [FileScanResult] = []

        for df in diffFiles {
            // Check extension filter (same as DirectoryScanner)
            let url = URL(fileURLWithPath: df.path)
            let fileName = url.lastPathComponent
            let ext = url.pathExtension.lowercased()
            let isEnvFile = DotenvClassifier.isDotenvFile(fileName)

            guard isEnvFile || DirectoryScanner.allowedExtensions.contains(ext) else {
                continue
            }

            // Get file content
            let content: String
            if staged && !unstaged {
                // Staged only: get from git index
                guard let staged = try? runGit(["show", ":\(df.path)"]) else { continue }
                content = staged
            } else {
                // Unstaged or both: read from disk
                guard let disk = try? String(contentsOfFile: df.path, encoding: .utf8) else {
                    continue
                }
                content = disk
            }

            guard !content.isEmpty else { continue }

            let parsedExt = isEnvFile ? "env" : ext
            var fileMatches = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: parsedExt,
                relativePath: df.path, config: config
            )

            fileMatches = Allowlist.filterInlineAllow(matches: fileMatches, content: content)

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
    static func runGit(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw GitDiffError.gitCommandFailed(arguments.joined(separator: " "))
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
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
