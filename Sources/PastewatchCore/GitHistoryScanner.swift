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
    // WO-662@v3: line-limit skips remain visible without changing existing history fields.
    public let skippedOverLimit: Int

    // WO-662@v3: existing construction defaults to zero skips.
    public init(findings: [CommitFinding], commitsScanned: Int, filesScanned: Int, skippedOverLimit: Int = 0) {
        self.findings = findings
        self.commitsScanned = commitsScanned
        self.filesScanned = filesScanned
        self.skippedOverLimit = skippedOverLimit
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

    // WO-675@v2: history scans own their skip diagnostics independently of accumulated coverage.
    // WO-662@v3: history shares source decoding and counts individual line-limit skips.
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
        bail: Bool = false,
        limits: ScanInputLimits = .current()
    ) throws -> GitLogScanResult {
        let output = try runGitLog(
            range: range,
            since: since,
            branch: branch,
            limits: limits
        )
        let chunks = parseCommitChunks(output)

        var findings: [CommitFinding] = []
        var seenFingerprints = Set<String>()
        // WO-662@v3: successful scans and line-limit skips are distinct measurements.
        var statistics = DirectoryScanStatistics()

        for chunk in chunks {
            let diffFiles = GitDiffScanner.parseDiff(chunk.diffContent)

            for df in diffFiles {
                // WO-562@v3: history scanning shares the canonical file classifier.
                guard GitScanHelpers.shouldScanFile(df.path) else { continue }
                // WO-662@v3: retain raw blob bytes until the file's source extension selects decoding.
                let data: Data
                do {
                    data = try GitDiffScanner.runGitData(
                        ["show", "\(chunk.hash):\(df.path)"],
                        limits: limits
                    )
                } catch let error as ScanInputLimitError {
                    // WO-599@v2: bounded history blobs fail the scan instead of disappearing.
                    throw error
                } catch let error as ScanInputTextError {
                    // WO-602@v2: malformed historical text cannot be skipped as absent.
                    throw error
                } catch {
                    continue
                }
                // WO-662@v3: only a long-line member is skipped; whole-file limits retain their error contract.
                let input: DirectoryScanner.DetectionInput
                var fileMatches: [DetectedMatch]
                do {
                    let ext = GitScanHelpers.scanExtension(for: df.path)
                    input = try DirectoryScanner.decodeScanData(data, ext: ext, limits: limits)
                    guard !input.content.isEmpty else { continue }
                    fileMatches = try input.scan(ext: ext, path: df.path, config: config)
                } catch let error as ScanInputLimitError {
                    guard case .lineBytes = error else { throw error }
                    statistics.recordOverLimit(path: df.path, error: error)
                    // WO-675@v2: retain exactly one path-only diagnostic for the skipped historical blob.
                    FileHandle.standardError.write(Data("Skipped over-limit file \(df.path): \(error.localizedDescription)\n".utf8))
                    continue
                }
                let content = input.content
                statistics.recordScanned()
                fileMatches = Allowlist.filterInlineAllow(matches: fileMatches, content: content)
                fileMatches = Allowlist.fromConfig(config).filter(fileMatches)

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
                        // WO-662@v3: early return retains actual scan and skip counts.
                        filesScanned: statistics.filesScanned, skippedOverLimit: statistics.skippedOverLimit
                    )}
                }
            }
        }

        return GitLogScanResult(
            findings: findings,
            commitsScanned: chunks.count,
            // WO-662@v3: skipped blobs never inflate the successful scan count.
            filesScanned: statistics.filesScanned, skippedOverLimit: statistics.skippedOverLimit
        )
    }

    // MARK: - Git log command

    // WO-662@v3: history patch hunks use extension-scoped legacy decoding, not metadata-wide fallback.
    static func runGitLog(
        range: String?,
        since: String?,
        branch: String?,
        limits: ScanInputLimits = .current()
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
        // WO-662@v3: preserve invalid-encoding failures outside newly admitted source hunks.
        return try GitDiffScanner.runGitPatch(args, limits: limits)
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

    // MARK: - Dedup

    /// Compute a fingerprint for deduplication: SHA256(type + ":" + value).
    private static func fingerprint(_ match: DetectedMatch) -> String {
        let input = match.type.rawValue + ":" + match.value
        let digest = SHA256.hash(data: Data(input.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
