import Foundation

// WO-670@v1: diagnostics serialize loading evidence without any allow-file values.
public struct ProjectAllowlistResolution: Encodable {
    public let path: String?
    public let loaded: Bool
    public let effectiveEntries: Int
    public let ignoredIntrinsicEntries: Int
    public let status: String
    // WO-670@v1: raw entries are available only to filtering, never diagnostic encoding.
    public let allowlist: Allowlist

    // WO-670@v1: an explicit wire projection excludes the private exact values.
    private enum CodingKeys: String, CodingKey {
        case path, loaded, effectiveEntries, ignoredIntrinsicEntries, status
    }
}

/// Manages allowed values that should be excluded from scan results.
public struct Allowlist {
    public let values: Set<String>
    public let patterns: [NSRegularExpression]
    // WO-672@v1: exact exemptions retain the source that granted them.
    public let valueSources: [String: Set<AllowlistSource>]
    public let patternSources: [Set<AllowlistSource>]

    // WO-672@v1: unannotated caller-supplied entries have no operator authority.
    public init(values: Set<String> = [], patterns: [NSRegularExpression] = [], source: AllowlistSource = .remedy) {
        self.values = values
        self.patterns = patterns
        // WO-672@v1: source metadata is not supplied by the allowlist file contents.
        valueSources = Dictionary(uniqueKeysWithValues: values.map { ($0, [source]) })
        patternSources = Array(repeating: [source], count: patterns.count)
    }

    // WO-672@v1: combining tiers must not lose operator exact-value authority.
    private init(values: Set<String>, patterns: [NSRegularExpression], valueSources: [String: Set<AllowlistSource>],
                 patternSources: [Set<AllowlistSource>]) {
        self.values = values
        self.patterns = patterns
        self.valueSources = valueSources
        self.patternSources = patternSources
    }

    // WO-670@v1: explicit files and discovered files share exact-value parsing, never patterns.
    /// Load allowlist from a file (one value per line, # comments).
    public static func load(from path: String) throws -> Allowlist {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        return Allowlist(values: parsedValues(content))
    }

    // WO-670@v1: rootless text never selects a project through process-directory state.
    public static func projectFile(for targetPath: String?, scanRoot: String? = nil) -> ProjectAllowlistResolution {
        guard let targetPath else {
            return ProjectAllowlistResolution(path: nil, loaded: false, effectiveEntries: 0,
                    ignoredIntrinsicEntries: 0, status: "pathless", allowlist: Allowlist(source: .projectFile))
        }
        let target = URL(fileURLWithPath: targetPath).standardizedFileURL
        var isDirectory: ObjCBool = false
        _ = FileManager.default.fileExists(atPath: target.path, isDirectory: &isDirectory)
        let directory = isDirectory.boolValue ? target : target.deletingLastPathComponent()
        let root = gitRoot(for: directory.path) ?? scanRoot.map { URL(fileURLWithPath: $0).standardizedFileURL.path } ?? directory.path
        let path = URL(fileURLWithPath: root).appendingPathComponent(".pastewatch-allow").path
        guard ConfigValidator.pathExistsIncludingDanglingSymlink(path, fileManager: .default) else {
            return ProjectAllowlistResolution(path: path, loaded: false, effectiveEntries: 0,
                    ignoredIntrinsicEntries: 0, status: "absent", allowlist: Allowlist(source: .projectFile))
        }
        do {
            let bytes = try DetectionRules.readBoundedFileData(atPath: path)
            guard let content = String(data: bytes, encoding: .utf8) else { throw CocoaError(.fileReadInapplicableStringEncoding) }
            let values = parsedValues(content)
            // WO-670@v1: intrinsic evidence in opt-in built-ins is ineffective here as well.
            var recognitionConfig = PastewatchConfig.defaultConfig
            recognitionConfig.enabledTypes = SensitiveDataType.allCases.map(\.rawValue)
            let ignored = values.filter { value in
                DetectionRules.scan(value, config: recognitionConfig).contains {
                    $0.value == value && $0.mutationAuthorizationSources.contains(.intrinsicFormat)
                }
            }
            let effective = values.subtracting(ignored)
            return ProjectAllowlistResolution(path: path, loaded: true, effectiveEntries: effective.count,
                    ignoredIntrinsicEntries: ignored.count, status: ignored.isEmpty ? "ok" : "warn",
                    allowlist: Allowlist(values: effective, source: .projectFile))
        } catch {
            // WO-670@v1: an unreadable file grants no exemptions and can never be reported active.
            return ProjectAllowlistResolution(path: path, loaded: false, effectiveEntries: 0,
                    ignoredIntrinsicEntries: 0, status: "warn", allowlist: Allowlist(source: .projectFile))
        }
    }

    // WO-670@v1: a single line syntax is shared by explicit and automatic exact-value files.
    private static func parsedValues(_ content: String) -> Set<String> {
        Set(content
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") })
    }

    // WO-670@v1: target-local Git discovery consumes no stdin and ignores ambient repository overrides.
    private static func gitRoot(for directory: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", directory, "rev-parse", "--show-toplevel"]
        process.environment = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("GIT_") }
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let output = Pipe()
        process.standardOutput = output
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0, var path = String(data: data, encoding: .utf8), path.hasPrefix("/") else { return nil }
            if path.hasSuffix("\n") { path.removeLast() }
            return path
        } catch { return nil }
    }

    // WO-672@v1: union source evidence as well as values when multiple tiers share an entry.
    /// Merge multiple allowlists.
    public func merged(with other: Allowlist) -> Allowlist {
        var sources = valueSources
        for (value, tiers) in other.valueSources { sources[value, default: []].formUnion(tiers) }
        return Allowlist(values: values.union(other.values), patterns: patterns + other.patterns, valueSources: sources,
                        patternSources: patternSources + other.patternSources)
    }

    // WO-672@v1: only the validated resolver or user loader may attach operator authority.
    /// Merge with config's allowedValues and allowedPatterns.
    public static func fromConfig(_ config: PastewatchConfig) -> Allowlist {
        // WO-672@v1: source metadata travels with each successfully compiled pattern.
        let compiled = config.allowedPatterns.compactMap { pattern -> (NSRegularExpression, Set<AllowlistSource>)? in
            guard let regex = try? NSRegularExpression(pattern: "^(\(pattern))$") else { return nil }
            return (regex, config.allowedPatternSources[pattern] ?? [.project])
        }
        // WO-672@v1: directly constructed or decoded policy defaults to project-tier exemptions.
        let sources = Dictionary(uniqueKeysWithValues: Set(config.allowedValues).map {
            ($0, config.allowedValueSources[$0] ?? [.project])
        })
        return Allowlist(values: Set(config.allowedValues), patterns: compiled.map { $0.0 }, valueSources: sources,
                        patternSources: compiled.map { $0.1 })
    }

    // WO-672@v1: shared authorization governs filtering before any surface can lose evidence.
    /// Filter matches, removing only source-authorized exact values or patterns.
    public func filter(_ matches: [DetectedMatch]) -> [DetectedMatch] {
        matches.filter { match in
            // WO-672@v1: pattern suppression never grants intrinsic-format authority.
            if valueSources[match.value]?.contains(where: {
                permitsAllowlistSuppression(of: match, source: $0, exactValue: true)
            }) == true { return false }
            for (pattern, sources) in zip(patterns, patternSources) where sources.contains(where: {
                permitsAllowlistSuppression(of: match, source: $0, exactValue: false)
            }) {
                let range = NSRange(match.value.startIndex..., in: match.value)
                if pattern.firstMatch(in: match.value, range: range) != nil { return false }
            }
            return true
        }
    }

    /// Check if a value is allowed (should be skipped).
    public func contains(_ value: String) -> Bool {
        values.contains(value)
    }

    /// WO-554@v3: only documented line or trailing comment forms can authorize a value.
    /// Requiring whitespace before the delimiter prevents URL fragments and operators
    /// from becoming accidental authorization markers.
    private static let inlineAllowPattern = try? NSRegularExpression(
        pattern: #"(?:^|\s)(?:#|//)\s*pastewatch:allow(?=\s|$)"#
    )

    // WO-672@v1: inline directives cannot hide intrinsic evidence from guards or mutation.
    /// Filter advisory matches on lines containing a pastewatch:allow directive.
    public static func filterInlineAllow(matches: [DetectedMatch], content: String) -> [DetectedMatch] {
        guard !matches.isEmpty, let inlineAllowPattern else { return matches }
        let lines = content.components(separatedBy: "\n")
        return matches.filter { match in
            // WO-672@v1: the directive's source is always unprivileged, even in trusted files.
            guard permitsAllowlistSuppression(of: match, source: .inlineDirective, exactValue: false) else { return true }
            let lineIndex = match.line - 1
            guard lineIndex >= 0, lineIndex < lines.count else { return true }
            let line = lines[lineIndex]
            let range = NSRange(line.startIndex..<line.endIndex, in: line)
            return inlineAllowPattern.firstMatch(in: line, range: range) == nil
        }
    }
}
