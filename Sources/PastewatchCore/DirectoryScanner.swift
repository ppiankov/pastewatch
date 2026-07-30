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

    /// File extensions to scan.
    public static let allowedExtensions: Set<String> = [
        "env", "yml", "yaml", "json", "toml", "conf", "xml", "tf",
        "sh", "py", "go", "js", "ts", "rb", "swift", "java",
        "properties", "cfg", "ini", "txt", "md", "pem", "key"
    ]

    /// Directories to skip.
    public static let skipDirectories: Set<String> = [
        ".git", "node_modules", ".build", "vendor", "DerivedData",
        ".swiftpm", "__pycache__", "dist", "build", ".tox"
    ]

    /// Scan all files in a directory recursively.
    public static func scan(
        directory: String,
        config: PastewatchConfig,
        ignoreFile: IgnoreFile? = nil,
        extraIgnorePatterns: [String] = [],
        bail: Bool = false,
        limits: ScanInputLimits = .current()
    ) throws -> [FileScanResult] {
        let dirURL = URL(fileURLWithPath: directory).standardizedFileURL
        let dirPath = dirURL.path
        var results: [FileScanResult] = []

        let mergedIgnore = mergedIgnoreFile(
            ignoreFile,
            extraPatterns: extraIgnorePatterns
        )

        guard let enumerator = FileManager.default.enumerator(
            at: dirURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .fileSizeKey],
            options: []
        ) else {
            return results
        }

        while let fileURL = enumerator.nextObject() as? URL {
            let fileName = fileURL.lastPathComponent

            // Skip directories in skiplist
            if skipDirectories.contains(fileName) {
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
                continue
            }

            // Skip binary files (check first 8192 bytes for null bytes)
            guard !isBinaryFile(at: fileURL) else {
                continue
            }

            // Read and scan
            let data: Data
            do {
                data = try DetectionRules.readBoundedFileData(
                    atPath: fileURL.path,
                    limits: limits
                )
            } catch let error as ScanInputLimitError {
                throw error
            } catch {
                continue
            }
            // WO-602@v2: a supported text file cannot disappear from aggregate evidence.
            guard let content = String(data: data, encoding: .utf8) else {
                throw ScanInputTextError.invalidUTF8
            }
            guard !content.isEmpty else { continue }

            // Format-aware scanning
            let parsedExt = isEnvFile ? "env" : fileURL.pathExtension.lowercased()
            var fileMatches = try scanFileContentOrThrow(
                content: content, ext: parsedExt,
                relativePath: relativePath, config: config,
                limits: limits
            )

            fileMatches = Allowlist.filterInlineAllow(matches: fileMatches, content: content)
            fileMatches = Allowlist.fromConfig(config).filter(fileMatches)

            if !fileMatches.isEmpty {
                results.append(FileScanResult(
                    filePath: relativePath,
                    matches: fileMatches,
                    content: content
                ))
                if bail { return results }
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
            return sorted
        }
        return sorted.map { result in
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
                sourceMatch(match, range: match.range, line: match.line, filePath: relativePath)
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
                sourceMatch(match, range: match.range, line: match.line, filePath: relativePath)
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
                    filePath: relativePath
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
                    filePath: relativePath
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

    /// WO-549@v2: source metadata rebasing must retain authorization provenance.
    private static func sourceMatch(
        _ match: DetectedMatch,
        range: Range<String.Index>,
        line: Int,
        filePath: String
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
            obfuscateRuleIdentifier: match.obfuscateRuleIdentifier
        )
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

    /// Check if a file appears to be binary by looking for null bytes.
    private static func isBinaryFile(at url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return true
        }
        defer { handle.closeFile() }

        let data = handle.readData(ofLength: 8192)
        return data.contains(0)
    }
}
