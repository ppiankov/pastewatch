#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// Result of scanning a single commit.
public struct CommitFinding {
    public let commitHash: String
    public let author: String
    public let date: String
    public let filePath: String
    public let matches: [DetectedMatch]

    public init(commitHash: String, author: String, date: String,
                filePath: String, matches: [DetectedMatch]) {
        self.commitHash = commitHash
        self.author = author
        self.date = date
        self.filePath = filePath
        self.matches = matches
    }
}

/// Aggregate result from git history scanning.
public struct GitLogScanResult {
    public let findings: [CommitFinding]
    public let commitsScanned: Int
    public let filesScanned: Int

    public init(findings: [CommitFinding], commitsScanned: Int, filesScanned: Int) {
        self.findings = findings
        self.commitsScanned = commitsScanned
        self.filesScanned = filesScanned
    }
}

/// Parsed metadata for a single commit chunk.
struct CommitChunk {
    let hash: String
    let author: String
    let date: String
    let diffContent: String
}

/// Scans git commit history for secrets, reporting only the first introduction of each finding.
public struct GitHistoryScanner {

    /// Marker prefix used in git log --format to delimit commits.
    static let commitMarker = "PWCOMMIT "

    /// Scan git history for secrets.
    ///
    /// - Parameters:
    ///   - range: Git revision range (e.g., "HEAD~50..HEAD"). Nil = all history.
    ///   - since: Only commits after this date (ISO format).
    ///   - branch: Specific branch to scan. Nil with nil range = --all.
    ///   - config: Pastewatch configuration.
    ///   - bail: Stop at first finding.
    /// - Returns: Scan result with findings, commit count, and file count.
    public static func scan(
        range: String? = nil,
        since: String? = nil,
        branch: String? = nil,
        config: PastewatchConfig,
        bail: Bool = false
    ) throws -> GitLogScanResult {
        let output = try runGitLog(range: range, since: since, branch: branch)
        let chunks = parseCommitChunks(output)

        var findings: [CommitFinding] = []
        var seenFingerprints = Set<String>()
        var filesScanned = 0

        for chunk in chunks {
            let diffFiles = GitDiffScanner.parseDiff(chunk.diffContent)

            for df in diffFiles {
                guard shouldScanFile(df.path) else { continue }
                filesScanned += 1

                guard let content = try? GitDiffScanner.runGit(
                    ["show", "\(chunk.hash):\(df.path)"]
                ), !content.isEmpty else { continue }

                let ext = scanExtension(for: df.path)
                var fileMatches = try DirectoryScanner.scanFileContentOrThrow(
                    content: content, ext: ext,
                    relativePath: df.path, config: config
                )
                fileMatches = Allowlist.filterInlineAllow(
                    matches: fileMatches, content: content
                )

                // Filter to only added lines
                fileMatches = fileMatches.filter { df.addedLines.contains($0.line) }

                // Dedup: skip findings already seen in earlier commits
                var newMatches: [DetectedMatch] = []
                for match in fileMatches {
                    let fp = fingerprint(match)
                    if !seenFingerprints.contains(fp) {
                        seenFingerprints.insert(fp)
                        newMatches.append(match)
                    }
                }

                if !newMatches.isEmpty {
                    findings.append(CommitFinding(
                        commitHash: chunk.hash,
                        author: chunk.author,
                        date: chunk.date,
                        filePath: df.path,
                        matches: newMatches
                    ))
                    if bail { return GitLogScanResult(
                        findings: findings,
                        commitsScanned: chunks.count,
                        filesScanned: filesScanned
                    )}
                }
            }
        }

        return GitLogScanResult(
            findings: findings,
            commitsScanned: chunks.count,
            filesScanned: filesScanned
        )
    }

    // MARK: - Git log command

    static func runGitLog(
        range: String?,
        since: String?,
        branch: String?
    ) throws -> String {
        var args = [
            "log", "--reverse", "-p", "--no-color",
            "--diff-filter=d",
            "--format=\(commitMarker)%H %ae %aI",
        ]
        if let since = since {
            args.append("--since=\(since)")
        }
        if let range = range {
            args.append(range)
        } else if let branch = branch {
            args.append(branch)
        } else {
            args.append("--all")
        }
        return try GitDiffScanner.runGit(args)
    }

    // MARK: - Parsing

    /// Split git log output into per-commit chunks.
    static func parseCommitChunks(_ output: String) -> [CommitChunk] {
        guard !output.isEmpty else { return [] }

        var chunks: [CommitChunk] = []
        let lines = output.components(separatedBy: "\n")
        var currentChunk: CommitChunk?
        var currentDiffLines: [String] = []

        for line in lines {
            if line.hasPrefix(commitMarker) {
                // Flush previous chunk
                if let chunk = currentChunk {
                    chunks.append(CommitChunk(
                        hash: chunk.hash, author: chunk.author,
                        date: chunk.date,
                        diffContent: currentDiffLines.joined(separator: "\n")
                    ))
                }
                // Parse new commit metadata: "PWCOMMIT <hash> <author> <date>"
                let parts = String(line.dropFirst(commitMarker.count))
                    .split(separator: " ", maxSplits: 2)
                    .map { String($0) }
                if parts.count >= 3 {
                    currentChunk = CommitChunk(
                        hash: parts[0], author: parts[1],
                        date: parts[2], diffContent: ""
                    )
                } else {
                    currentChunk = nil
                }
                currentDiffLines = []
            } else {
                currentDiffLines.append(line)
            }
        }

        // Flush last chunk
        if let chunk = currentChunk {
            chunks.append(CommitChunk(
                hash: chunk.hash, author: chunk.author,
                date: chunk.date,
                diffContent: currentDiffLines.joined(separator: "\n")
            ))
        }

        return chunks
    }

    // MARK: - File filtering

    /// Check if a file path should be scanned (by extension).
    private static func shouldScanFile(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        let fileName = url.lastPathComponent
        if DotenvClassifier.isDotenvFile(fileName) { return true }
        return DirectoryScanner.allowedExtensions.contains(
            url.pathExtension.lowercased()
        )
    }

    /// Get the effective extension for scanning (handles .env files).
    private static func scanExtension(for path: String) -> String {
        let url = URL(fileURLWithPath: path)
        let fileName = url.lastPathComponent
        if DotenvClassifier.isDotenvFile(fileName) { return "env" }
        return url.pathExtension.lowercased()
    }

    // MARK: - Dedup

    /// Compute a fingerprint for deduplication: SHA256(type + ":" + value).
    private static func fingerprint(_ match: DetectedMatch) -> String {
        let input = match.type.rawValue + ":" + match.value
        let digest = SHA256.hash(data: Data(input.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
