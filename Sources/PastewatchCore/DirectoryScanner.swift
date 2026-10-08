import Foundation

/// WO-549@v2: callers must fail closed when a parsed secret cannot be mapped back
/// to the original bytes without risking mutation of a different occurrence.
public struct StructuredMatchRangeError: LocalizedError {
    public let filePath: String
    public let line: Int

    public var errorDescription: String? {
        "Cannot safely map a structured finding in \(filePath) at line \(line)."
    }
}

/// Result of scanning a single file.
public struct FileScanResult {
    public let filePath: String
    public let matches: [DetectedMatch]
    public let content: String
    public let gitignored: Bool

    public init(filePath: String, matches: [DetectedMatch], content: String, gitignored: Bool = false) {
        self.filePath = filePath
        self.matches = matches
        self.content = content
        self.gitignored = gitignored
    }
}

// WO-662@v3: coverage counts distinguish inspected files from findings and pruned subtrees.
public struct DirectoryScanStatistics: Codable {
    public fileprivate(set) var filesScanned = 0
    public fileprivate(set) var skippedUnsupported = 0
    public fileprivate(set) var skippedIgnored = 0
    public fileprivate(set) var skippedBinary = 0
    public fileprivate(set) var skippedEmpty = 0
    public fileprivate(set) var skippedUnreadable = 0
    public fileprivate(set) var skippedDirectories = 0
    // WO-662@v3: oversized lines are visible skips rather than whole-scan failures.
    public private(set) var skippedOverLimit = 0

    // WO-662@v3: shared scanners count inspected files independently of their findings.
    mutating func recordScanned() { filesScanned += 1 }

    // WO-662@v3: report only the affected path and limit, never its contents.
    mutating func recordOverLimit(path: String, error: ScanInputLimitError) {
        skippedOverLimit += 1
        FileHandle.standardError.write(Data("Skipped over-limit file \(path): \(error.localizedDescription)\n".utf8))
    }

    // WO-662@v3: a zero scan cannot be presented as evidence of a clean directory.
    public func summary(findings: Int) -> String {
        let skipped = "Skipped: unsupported=\(skippedUnsupported), ignored=\(skippedIgnored), "
            + "binary=\(skippedBinary), empty=\(skippedEmpty), unreadable=\(skippedUnreadable), "
            + "pruned-directories=\(skippedDirectories), skippedOverLimit=\(skippedOverLimit)."
        let warning = filesScanned == 0
            ? " No text files were scanned; results do not establish a clean directory." : ""
        return "Scanned \(filesScanned) files. Found \(findings) findings. \(skipped)\(warning)"
    }
}

// WO-662@v3: keep findings-only consumers compatible while exposing truthful directory coverage.
public struct DirectoryScanReport {
    public let files: [FileScanResult]
    public let statistics: DirectoryScanStatistics
}

/// Recursive directory scanner for sensitive data detection.
public struct DirectoryScanner {
    /// WO-549@v2: parser-local identity distinguishes repeated equal matches.
    private struct ParsedMatchKey: Hashable {
        let value: String
        let lowerOffset: Int
        let upperOffset: Int
    }

    /// WO-549@v2: retain cross-value claims while resetting parser-local identity
    /// for each structured value.
    private struct SourceRangeState {
        let content: String
        var parsedContent = ""
        var parsedValueRanges: [ParsedMatchKey: Range<String.Index>] = [:]
        var claimedSourceRanges: [String: [Range<String.Index>]] = [:]

        mutating func beginParsedValue(_ value: String) {
            parsedContent = value
            parsedValueRanges = [:]
        }
    }

    // WO-662@v3: these source formats are text; the existing binary probe still applies.
    /// File extensions to scan.
    public static let allowedExtensions: Set<String> = [
        "env", "yml", "yaml", "json", "toml", "conf", "xml", "tf",
        "sh", "py", "go", "js", "ts", "rb", "swift", "java",
        "properties", "cfg", "ini", "txt", "md", "pem", "key",
        "kt", "kts", "gradle", "c", "h", "cpp", "rs", "php", "cs", "html", "sql", "scala", "dart",
        // WO-662@v3: line-delimited JSON transcripts are text even when each line is a separate object.
        "jsonl", "ndjson"
    ]

    // WO-662@v3: legacy text encoding is detection-only and limited to newly admitted source formats.
    static let latin1DetectionExtensions: Set<String> = [
        "kt", "kts", "gradle", "c", "h", "cpp", "rs", "php", "cs", "html", "sql", "scala", "dart", "jsonl", "ndjson"
    ]

    // WO-662@v3: retain original byte limits and line positions when Latin-1 expands in UTF-8 memory.
    struct DetectionInput {
        let content: String
        let limits: ScanInputLimits
        let latin1Bytes: Data?

        // WO-662@v3: scanners share detection decoding without introducing a file-writing path.
        func scan(ext: String, path: String, config: PastewatchConfig) throws -> [DetectedMatch] {
            let matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: ext, relativePath: path, config: config, limits: limits
            )
            guard let bytes = latin1Bytes else { return matches }
            var lineStarts = [0]
            var previous: UInt8 = 0
            for (offset, byte) in bytes.enumerated() {
                if byte == 0x0A && previous == 0x0D { lineStarts[lineStarts.count - 1] = offset + 1 } else if byte == 0x0A || byte == 0x0D { lineStarts.append(offset + 1) }
                previous = byte
            }
            return matches.map { match in
                let offset = NSRange(match.range, in: content).location
                let line = lineStarts.prefix { $0 <= offset }.count
                return DetectedMatch(
                    type: match.type, value: match.value, range: match.range, line: line,
                    filePath: match.filePath, customRuleName: match.customRuleName, customSeverity: match.customSeverity,
                    advisory: match.advisory, mutationAuthorizationSources: match.mutationAuthorizationSources,
                    obfuscateRuleIdentifier: match.obfuscateRuleIdentifier, mutationSubrange: match.mutationSubrange
                )
            }
        }
    }

    // WO-662@v3: ISO-8859-1 maps every raw byte to one scalar; original formats retain strict UTF-8.
    static func decodeScanData(_ data: Data, ext: String, limits: ScanInputLimits) throws -> DetectionInput {
        if let content = String(data: data, encoding: .utf8) {
            return DetectionInput(content: content, limits: limits, latin1Bytes: nil)
        }
        guard latin1DetectionExtensions.contains(ext.lowercased()) else { throw ScanInputTextError.invalidUTF8 }
        try validateRawScanData(data, limits: limits)
        let content = String(String.UnicodeScalarView(data.map { UnicodeScalar($0) }))
        // Each validated Latin-1 byte requires at most two UTF-8 bytes; raw limits were already enforced.
        let expandedLineLimit = limits.maximumLineBytes > Int.max / 2 ? Int.max : limits.maximumLineBytes * 2
        return DetectionInput(
            content: content,
            limits: ScanInputLimits(maximumFileBytes: content.utf8.count, maximumLineBytes: expandedLineLimit),
            latin1Bytes: data
        )
    }

    // WO-662@v3: validate raw bytes before any encoding expansion changes their measured size.
    private static func validateRawScanData(_ data: Data, limits: ScanInputLimits) throws {
        guard data.count <= limits.maximumFileBytes else {
            throw ScanInputLimitError.fileBytes(actual: data.count, maximum: limits.maximumFileBytes)
        }
        var line = 1
        var count = 0
        var carriageReturn = false
        for byte in data {
            if byte == 0x0A || byte == 0x0D {
                if byte != 0x0A || !carriageReturn { line += 1 }
                count = 0
                carriageReturn = byte == 0x0D
            } else {
                carriageReturn = false
                count += 1
                if count > limits.maximumLineBytes {
                    throw ScanInputLimitError.lineBytes(line: line, actual: count, maximum: limits.maximumLineBytes)
                }
            }
        }
    }

    /// Directories to skip.
    public static let skipDirectories: Set<String> = [
        ".git", "node_modules", ".build", "vendor", "DerivedData",
        ".swiftpm", "__pycache__", "dist", "build", ".tox"
    ]

    // WO-662@v3: preserve the findings-only return contract for existing callers.
    /// Scan all files in a directory recursively.
    public static func scan(
        directory: String,
        config: PastewatchConfig,
        ignoreFile: IgnoreFile? = nil,
        extraIgnorePatterns: [String] = [],
        bail: Bool = false,
        limits: ScanInputLimits = .current()
    ) throws -> [FileScanResult] {
        try scanWithStatistics(
            directory: directory, config: config, ignoreFile: ignoreFile,
            extraIgnorePatterns: extraIgnorePatterns, bail: bail, limits: limits
        ).files
    }

    // WO-662@v3: traversal measures actual scans even when a file has no findings.
    public static func scanWithStatistics(
        directory: String,
        config: PastewatchConfig,
        ignoreFile: IgnoreFile? = nil,
        extraIgnorePatterns: [String] = [],
        bail: Bool = false,
        limits: ScanInputLimits = .current()
    ) throws -> DirectoryScanReport {
        let dirURL = URL(fileURLWithPath: directory).standardizedFileURL
        let dirPath = dirURL.path
        var results: [FileScanResult] = []
        var statistics = DirectoryScanStatistics()

        let mergedIgnore = mergedIgnoreFile(
            ignoreFile,
            extraPatterns: extraIgnorePatterns
        )

        guard let enumerator = FileManager.default.enumerator(
            at: dirURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .fileSizeKey],
            options: []
        ) else {
            return DirectoryScanReport(files: results, statistics: statistics)
        }

        while let fileURL = enumerator.nextObject() as? URL {
            let fileName = fileURL.lastPathComponent

            // Skip directories in skiplist
            if skipDirectories.contains(fileName) {
                // WO-662@v3: pruned subtrees are counted as directories, never guessed file totals.
                statistics.skippedDirectories += 1
                enumerator.skipDescendants()
                continue
            }

            // Check if it's a regular file
            guard let resourceValues = try? fileURL.resourceValues(
                forKeys: [.isRegularFileKey, .fileSizeKey]
            ),
                  resourceValues.isRegularFile == true else {
                continue
            }

            // Check extension (handle .env as special case -- no extension but starts with dot)
            let ext = fileURL.pathExtension.lowercased()
            let isEnvFile = DotenvClassifier.isDotenvFile(fileName)

            guard isEnvFile || allowedExtensions.contains(ext) else {
                // WO-662@v3: unsupported text must not disappear from coverage reporting.
                statistics.skippedUnsupported += 1
                continue
            }

            try validateFileSize(resourceValues.fileSize, limits: limits)

            // Compute relative path from the directory root
            let filePath = fileURL.standardizedFileURL.path
            let relativePath = filePath.hasPrefix(dirPath + "/")
                ? String(filePath.dropFirst(dirPath.count + 1))
                : fileURL.lastPathComponent

            // Skip files matching ignore patterns
            if let ignore = mergedIgnore, ignore.shouldIgnore(relativePath) {
                // WO-662@v3: explicit file ignores have a separate count from extension skips.
                statistics.skippedIgnored += 1
                continue
            }

            // WO-662@v3: classify read skips without hiding invalid encoding or input-limit failures.
            // WO-662@v3: a long line skips one member, while whole-file and original encoding failures still abort.
            let parsedExt = isEnvFile ? "env" : fileURL.pathExtension.lowercased()
            let input: DetectionInput
            var fileMatches: [DetectedMatch]
            do {
                guard let decoded = try readScanContent(at: fileURL, limits: limits, statistics: &statistics) else { continue }
                input = decoded
                fileMatches = try input.scan(ext: parsedExt, path: relativePath, config: config)
            } catch let error as ScanInputLimitError {
                guard case .lineBytes = error else { throw error }
                statistics.recordOverLimit(path: relativePath, error: error)
                continue
            }
            let content = input.content

            fileMatches = Allowlist.filterInlineAllow(matches: fileMatches, content: content)
            fileMatches = Allowlist.fromConfig(config).filter(fileMatches)
            // WO-662@v3: count successful scans, not only files that contribute findings.
            statistics.filesScanned += 1

            if !fileMatches.isEmpty {
                results.append(FileScanResult(
                    filePath: relativePath,
                    matches: fileMatches,
                    content: content
                ))
                // WO-662@v3: bail reports only work actually performed before the first finding.
                if bail { return DirectoryScanReport(files: results, statistics: statistics) }
            }
        }

        let sorted = results.sorted { $0.filePath < $1.filePath }

        // Tag gitignored files
        let ignoredSet = gitIgnoredFiles(
            in: directory,
            paths: sorted.map { $0.filePath },
            limits: limits
        )
        if ignoredSet.isEmpty {
            // WO-662@v3: coverage accompanies the unchanged findings list.
            return DirectoryScanReport(files: sorted, statistics: statistics)
        }
        // WO-662@v3: gitignored tagging does not change whether a file was inspected.
        let tagged = sorted.map { result in
            if ignoredSet.contains(result.filePath) {
                return FileScanResult(
                    filePath: result.filePath,
                    matches: result.matches,
                    content: result.content,
                    gitignored: true
                )
            }
            return result
        }
        // WO-662@v3: retain traversal evidence after findings metadata is tagged.
        return DirectoryScanReport(files: tagged, statistics: statistics)
    }

    // WO-662@v3: count binary, empty and unreadable skips while preserving fail-closed text validation.
    private static func readScanContent(
        at url: URL, limits: ScanInputLimits, statistics: inout DirectoryScanStatistics
    ) throws -> DetectionInput? {
        do {
            if try isBinaryFile(at: url) {
                statistics.skippedBinary += 1
                return nil
            }
            let data = try DetectionRules.readBoundedFileData(atPath: url.path, limits: limits)
            // WO-662@v3: only newly supported source extensions accept detection-only Latin-1.
            let input = try decodeScanData(data, ext: url.pathExtension, limits: limits)
            guard !input.content.isEmpty else {
                statistics.skippedEmpty += 1
                return nil
            }
            return input
        } catch let error as ScanInputLimitError {
            throw error
        } catch let error as ScanInputTextError {
            throw error
        } catch {
            statistics.skippedUnreadable += 1
            return nil
        }
    }

    // WO-595@v2: reject a directory member before decode without growing traversal complexity.
    private static func validateFileSize(
        _ fileSize: Int?,
        limits: ScanInputLimits
    ) throws {
        guard let fileSize, fileSize > limits.maximumFileBytes else { return }
        throw ScanInputLimitError.fileBytes(
            actual: fileSize,
            maximum: limits.maximumFileBytes
        )
    }

    // WO-595@v2: keep limit-aware traversal below the scanner complexity gate.
    private static func mergedIgnoreFile(
        _ ignoreFile: IgnoreFile?,
        extraPatterns: [String]
    ) -> IgnoreFile? {
        guard let ignoreFile else {
            return extraPatterns.isEmpty ? nil : IgnoreFile(patterns: extraPatterns)
        }
        guard !extraPatterns.isEmpty else { return ignoreFile }
        return IgnoreFile(patterns: ignoreFile.patterns + extraPatterns)
    }

    // WO-600@v2: drain git output while paths are written so neither pipe can block the other.
    /// Check which paths are gitignored using `git check-ignore`.
    /// Returns empty set if not in a git repo or git is not available.
    public static func gitIgnoredFiles(
        in directory: String,
        paths: [String],
        limits: ScanInputLimits = .current()
    ) -> Set<String> {
        guard !paths.isEmpty else { return [] }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", directory, "check-ignore", "--stdin"]
        process.currentDirectoryURL = URL(fileURLWithPath: directory)

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return []
        }

        let inputHandle = inputPipe.fileHandleForWriting
        let writerGroup = DispatchGroup()
        writerGroup.enter()
        DispatchQueue.global(qos: .utility).async {
            defer {
                try? inputHandle.close()
                writerGroup.leave()
            }
            // WO-600@v2: stream paths so the deadlock fix does not duplicate the full input.
            for path in paths {
                do {
                    try inputHandle.write(contentsOf: Data((path + "\n").utf8))
                } catch {
                    break
                }
            }
        }

        let data: Data
        do {
            data = try DetectionRules.readBoundedInputData(
                from: outputPipe.fileHandleForReading,
                limits: limits
            )
        } catch {
            if process.isRunning {
                process.terminate()
            }
            writerGroup.wait()
            process.waitUntilExit()
            return []
        }

        writerGroup.wait()
        process.waitUntilExit()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        return Set(
            output.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        )
    }

    /// Scan file content using format-aware parsing when available.
    public static func scanFileContent(
        content: String, ext: String,
        relativePath: String, config: PastewatchConfig
    ) -> [DetectedMatch] {
        (try? scanFileContentOrThrow(
            content: content,
            ext: ext,
            relativePath: relativePath,
            config: config
        )) ?? []
    }

    // WO-639: pass index-owning strings to source metadata rebasing without changing parsing or range lookup.
    /// WO-128: scan file content without hiding configured shared-pattern load failures.
    public static func scanFileContentOrThrow(
        content: String,
        ext: String,
        relativePath: String,
        config: PastewatchConfig,
        customRules: [CustomRule] = [],
        limits: ScanInputLimits = .current()
    ) throws -> [DetectedMatch] {
        // WO-595@v2: structured parsing must not bypass whole-file and line limits.
        try DetectionRules.validateFileInput(content, limits: limits)
        guard let parser = parserForExtension(ext, config: config) else {
            return try DetectionRules.scanFileIOOrThrow(
                content,
                config: config,
                customRules: customRules,
                limits: limits
            ).map { match in
                // WO-639: raw matches already use source indices but still need identity verification.
                sourceMatch(match, range: match.range, line: match.line, filePath: relativePath,
                            parsedContent: content, source: content)
            }
        }

        // WO-128: fail once before parsed-value scanning can return partial results.
        try DetectionRules.ensureSharedPatternsLoaded(config: config)

        // Format-aware: extract values and scan each
        let parsedValues = parser.parseValues(from: content)
        // WO-550@v2: an empty structured parse is not proof that non-empty input is
        // clean. Preserve the raw diagnostic scan as the fail-closed fallback.
        if parsedValues.isEmpty, !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return try DetectionRules.scanFileIOOrThrow(
                content,
                config: config,
                customRules: customRules,
                limits: limits
            ).map { match in
                // WO-639: preserve raw targeting when a structured parser yields no values.
                sourceMatch(match, range: match.range, line: match.line, filePath: relativePath,
                            parsedContent: content, source: content)
            }
        }

        var matches: [DetectedMatch] = []
        var sourceRangeState = SourceRangeState(content: content)
        for pv in parsedValues {
            sourceRangeState.beginParsedValue(pv.value)
            for vm in try DetectionRules.scanFileIOOrThrow(
                pv.value,
                config: config,
                customRules: customRules,
                limits: limits
            ) {
                guard let sourceRange = sourceRange(
                    of: vm.value,
                    line: pv.line,
                    parsedRange: vm.range,
                    state: &sourceRangeState
                ) else {
                    throw StructuredMatchRangeError(filePath: relativePath, line: pv.line)
                }
                matches.append(sourceMatch(
                    vm,
                    range: sourceRange,
                    line: lineNumber(at: sourceRange.lowerBound, in: content),
                    // WO-639: parsed-value indices must be translated into the full source file.
                    filePath: relativePath, parsedContent: pv.value, source: content
                ))
            }

            // Key-aware credential detection: if the key name contains a credential
            // keyword and the value looks like a real secret, flag it.
            // This catches JSON {"API_KEY": "value"} where the value alone has no pattern.
            if let key = pv.key,
               DetectionRules.isCredentialKeyName(key),
               DetectionRules.isValidCredentialValue(pv.value) {
                guard let sourceRange = sourceRange(
                   of: pv.value,
                   line: pv.line,
                   parsedRange: pv.value.startIndex..<pv.value.endIndex,
                   state: &sourceRangeState
                ) else {
                    throw StructuredMatchRangeError(filePath: relativePath, line: pv.line)
                }
                guard !matches.contains(where: {
                   $0.type == .credential && $0.range == sourceRange
                }) else {
                    continue
                }
                matches.append(sourceMatch(
                    DetectedMatch(
                        type: .credential,
                        value: pv.value,
                        range: pv.value.startIndex..<pv.value.endIndex
                    ),
                    range: sourceRange,
                    line: lineNumber(at: sourceRange.lowerBound, in: content),
                    // WO-639: the shared source-copy path also accepts key-aware matches with no subrange.
                    filePath: relativePath, parsedContent: pv.value, source: content
                ))
            }
        }

        // XML files: also run raw detection for XML-specific tag patterns
        // (e.g., <password>plain</password> where the extracted value alone
        // wouldn't match any pattern rule)
        if ext.lowercased() == "xml" {
            let rawMatches = try DetectionRules.scanFileIOOrThrow(
                content,
                config: config,
                customRules: customRules,
                limits: limits
            )
            for rm in rawMatches {
                // Only add XML-specific types not already found
                guard rm.type == .xmlCredential || rm.type == .xmlUsername || rm.type == .xmlHostname else {
                    continue
                }
                let alreadyFound = matches.contains { $0.line == rm.line && $0.type == rm.type }
                if !alreadyFound {
                    matches.append(DetectedMatch(
                        type: rm.type, value: rm.value, range: rm.range,
                        line: rm.line, filePath: relativePath,
                        customRuleName: rm.customRuleName, customSeverity: rm.customSeverity
                    ))
                }
            }
        }

        return matches
    }

    // WO-639: internal visibility lets tests force a verification mismatch through the production copy path.
    // WO-549@v2: source metadata rebasing must retain authorization provenance.
    // swiftlint:disable:next function_parameter_count
    static func sourceMatch(
        _ match: DetectedMatch,
        range: Range<String.Index>,
        line: Int,
        filePath: String,
        parsedContent: String,
        source: String
    ) -> DetectedMatch {
        DetectedMatch(
            type: match.type,
            value: match.value,
            range: range,
            line: line,
            filePath: filePath,
            customRuleName: match.customRuleName,
            customSeverity: match.customSeverity,
            advisory: match.advisory,
            mutationAuthorizationSources: match.mutationAuthorizationSources,
            // WO-639: a failed rebase drops only optional targeting, retaining whole-match authorization.
            obfuscateRuleIdentifier: match.obfuscateRuleIdentifier,
            mutationSubrange: rebasedMutationSubrange(match, range: range, parsedContent: parsedContent, source: source)
        )
    }

    // WO-639: verify container identity, then translate relative bytes using each string's own UTF-8 view.
    private static func rebasedMutationSubrange(
        _ match: DetectedMatch, range: Range<String.Index>, parsedContent: String, source: String
    ) -> Range<String.Index>? {
        guard let span = match.mutationSubrange, !span.isEmpty,
              match.range.lowerBound >= parsedContent.startIndex, match.range.upperBound <= parsedContent.endIndex,
              span.lowerBound >= match.range.lowerBound, span.upperBound <= match.range.upperBound,
              range.lowerBound >= source.startIndex, range.upperBound <= source.endIndex,
              String(parsedContent[match.range]) == match.value, String(source[range]) == match.value,
              source[range].utf8.elementsEqual(match.value.utf8) else { return nil }
        let offset = parsedContent.utf8.distance(from: match.range.lowerBound, to: span.lowerBound)
        let length = parsedContent.utf8.distance(from: span.lowerBound, to: span.upperBound)
        guard offset >= 0, length > 0, offset <= match.value.utf8.count,
              length <= match.value.utf8.count - offset,
              let lowerByte = source.utf8.index(range.lowerBound, offsetBy: offset, limitedBy: range.upperBound),
              let upperByte = source.utf8.index(lowerByte, offsetBy: length, limitedBy: range.upperBound),
              let lower = String.Index(lowerByte, within: source), let upper = String.Index(upperByte, within: source),
              source[lower..<upper].utf8.elementsEqual(parsedContent[span].utf8) else { return nil }
        return lower..<upper
    }

    /// WO-549@v2: parsed values must be rebased to the source string before callers
    /// mutate content. A parser-local range cannot safely index the full file.
    private static func sourceRange(
        of value: String,
        line: Int,
        parsedRange: Range<String.Index>,
        state: inout SourceRangeState
    ) -> Range<String.Index>? {
        let key = ParsedMatchKey(
            value: value,
            lowerOffset: state.parsedContent.distance(
                from: state.parsedContent.startIndex,
                to: parsedRange.lowerBound
            ),
            upperOffset: state.parsedContent.distance(
                from: state.parsedContent.startIndex,
                to: parsedRange.upperBound
            )
        )
        if let cached = state.parsedValueRanges[key] {
            return cached
        }

        let claimed = state.claimedSourceRanges[value] ?? []
        var searchRanges: [Range<String.Index>] = []
        if line > 0, let lineRange = sourceLineRange(line, in: state.content) {
            searchRanges.append(lineRange)
        }
        // JSON's Foundation parser reports the first line for duplicate decoded
        // values. Only broaden after a prior occurrence proves this is a duplicate;
        // otherwise a decoded escape could be mapped to unrelated plaintext.
        if line <= 0 || !claimed.isEmpty {
            searchRanges.append(state.content.startIndex..<state.content.endIndex)
        }

        for searchRange in searchRanges {
            var cursor = searchRange.lowerBound
            while cursor < searchRange.upperBound,
                  let candidate = state.content.range(
                      of: value,
                      range: cursor..<searchRange.upperBound
                  ) {
                if !claimed.contains(candidate) {
                    state.parsedValueRanges[key] = candidate
                    state.claimedSourceRanges[value, default: []].append(candidate)
                    return candidate
                }
                cursor = candidate.upperBound
            }
        }
        return nil
    }

    private static func sourceLineRange(
        _ line: Int,
        in content: String
    ) -> Range<String.Index>? {
        var lineStart = content.startIndex
        if line > 1 {
            for _ in 1..<line {
                guard let newline = content[lineStart...].firstIndex(of: "\n") else {
                    return nil
                }
                lineStart = content.index(after: newline)
            }
        }
        let lineEnd = content[lineStart...].firstIndex(of: "\n") ?? content.endIndex
        return lineStart..<lineEnd
    }

    private static func lineNumber(
        at index: String.Index,
        in content: String
    ) -> Int {
        content[..<index].reduce(into: 1) { line, character in
            if character == "\n" {
                line += 1
            }
        }
    }

    // WO-662@v3: failure to open a file is unreadable, not evidence that its bytes are binary.
    /// Check if a file appears to be binary by looking for null bytes.
    private static func isBinaryFile(at url: URL) throws -> Bool {
        let handle = try FileHandle(forReadingFrom: url)
        defer { handle.closeFile() }

        let data = handle.readData(ofLength: 8192)
        return data.contains(0)
    }
}
