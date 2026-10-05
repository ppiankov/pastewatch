import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// WO-647@v2: expose only the redacted view and metadata needed to reuse the whole-file read decision.
public struct RedactedFileView {
    public let content: String // WO-647@v2: authorized values have already been replaced with restorable markers.
    public let viewToken: String // WO-647@v2: hash only the whole redacted view, never private source bytes.
    public let redactions: [RedactionEntry] // WO-647@v2: manifests contain types, lines and markers only.
}

// WO-647@v2: successful edits report counts rather than file content or matched values.
public struct RedactedEditSummary {
    public let linesChanged: Int // WO-647@v2: count affected lines after excluding unchanged context.
    public let redactions: Int // WO-647@v2: count the whole-file read's verified replacements.
}

// WO-647@v2: bind a literal edit and its optional whole-file consistency check into one request.
public struct RedactedEditRequest {
    public let filePath: String // WO-647@v2: mappings and the atomic replacement are scoped to this file.
    public let oldString: String // WO-647@v2: one unique byte-literal span from the redacted view.
    public let newString: String // WO-647@v2: agent-controlled text is scanned before restoring placeholders.
    public let expectedViewToken: String? // WO-647@v2: optional for session MCP, required by the separate CLI surface.

    // WO-647@v2: capture the edit without exposing any plaintext values in diagnostics.
    public init(filePath: String, oldString: String, newString: String, expectedViewToken: String? = nil) {
        self.filePath = filePath
        self.oldString = oldString
        self.newString = newString
        self.expectedViewToken = expectedViewToken
    }
}

// WO-647@v2: refusal messages discard file content, snippets and underlying filesystem error details.
public enum RedactedEditError: LocalizedError {
    case inspectionFailed, invalidLineRange, notFound, partialPlaceholder, writeFailed, changedSinceRead
    case ambiguous(Int), unresolved(Int), plaintextSecrets([String])

    // WO-647@v2: error payloads carry only fixed messages, counts, and type/line summaries.
    public var errorDescription: String? {
        switch self {
        case .inspectionFailed: return "Edit refused: could not inspect a regular UTF-8 file"
        case .invalidLineRange: return "Read refused: line ranges must be positive"
        case .notFound: return "Edit refused: old_string not found"
        case .ambiguous(let count): return "Edit refused: old_string matches \(count) locations"
        case .partialPlaceholder: return "Edit refused: partial placeholder token"
        case .unresolved(let count): return "Edit refused: \(count) unresolved placeholder(s)"
        case .plaintextSecrets(let findings): return "Edit refused: plaintext secrets: " + findings.joined(separator: ", ")
        case .writeFailed: return "Edit refused: atomic replacement failed"
        case .changedSinceRead: return "Edit refused: file changed since read"
        }
    }
}

// WO-647@v2: MCP and CLI partial edits share one whole-file authorization, restoration and atomic write path.
public enum RedactedEdit {
    private static let newlineByte: UInt8 = 0x0A // WO-647@v2: line windows split only on UTF-8 LF boundaries.
    // WO-647@v2: retain private source bytes only long enough to restore and commit a verified replacement.
    private struct Snapshot {
        let bytes: Data // WO-647@v2: used for a final unchanged-file check, never returned to the caller.
        let view: RedactedFileView // WO-647@v2: the externally visible representation is already redacted.
        let mode: NSNumber // WO-647@v2: preserve the existing file's permissions during atomic replacement.
    }

    // WO-647@v2: callers may select lines only after a complete file inspection and placeholder mapping.
    public static func read(
        filePath: String, store: RedactionStore, config: PastewatchConfig,
        startLine: Int? = nil, lineCount: Int? = nil
    ) throws -> RedactedFileView {
        let snapshot = try inspect(filePath: filePath, store: store, config: config)
        let text = try selectLines(snapshot.view.content, startLine: startLine, lineCount: lineCount)
        // WO-647@v2: line windows retain the token computed from the complete redacted view.
        return RedactedFileView(content: text, viewToken: snapshot.view.viewToken, redactions: snapshot.view.redactions)
    }

    // WO-647@v2: the public edit always uses the platform's atomic rename operation.
    public static func edit(
        filePath: String, oldString: String, newString: String, store: RedactionStore,
        config: PastewatchConfig
    ) throws -> RedactedEditSummary {
        try edit(RedactedEditRequest(filePath: filePath, oldString: oldString, newString: newString),
                 store: store, config: config)
    }

    // WO-647@v2: consistency-checked callers still use the same atomic edit path.
    public static func edit(
        _ request: RedactedEditRequest, store: RedactionStore, config: PastewatchConfig
    ) throws -> RedactedEditSummary {
        try edit(request, store: store, config: config, replace: atomicReplace)
    }

    // WO-647@v2: an internal replacement seam proves failure leaves the original bytes intact.
    static func edit(
        _ request: RedactedEditRequest, store: RedactionStore, config: PastewatchConfig,
        replace: (URL, URL) throws -> Void
    ) throws -> RedactedEditSummary {
        let filePath = request.filePath
        let oldString = request.oldString
        let newString = request.newString
        let snapshot = try inspect(filePath: filePath, store: store, config: config)
        // WO-647@v2: consistency checks compare only redacted views; raw bytes remain internal to the final rename check.
        if let expectedViewToken = request.expectedViewToken, expectedViewToken.lowercased() != snapshot.view.viewToken {
            throw RedactedEditError.changedSinceRead
        }
        let bytes = Data(snapshot.view.content.utf8)
        let range = try uniqueRange(of: Data(oldString.utf8), in: bytes)
        let splitsMarker = store.placeholderByteRanges(in: snapshot.view.content).contains { marker in
            marker.overlaps(range) && (range.lowerBound > marker.lowerBound || range.upperBound < marker.upperBound)
        }
        guard !splitsMarker, !store.hasPartialPlaceholder(in: newString, filePath: filePath) else {
            throw RedactedEditError.partialPlaceholder
        }
        var edited = bytes
        edited.replaceSubrange(range, with: newString.utf8)
        guard let text = String(data: edited, encoding: .utf8) else { throw RedactedEditError.inspectionFailed }
        // WO-647@v2: inspect both edit boundaries while pre-existing authorized values are still placeholders.
        try validateEditedView(text, filePath: filePath, config: config)
        let restored: ResolveResult
        do {
            restored = try store.resolveChecked(content: text, filePath: filePath,
                                                 maximumBytes: ScanInputLimits.current().maximumFileBytes)
        } catch { throw RedactedEditError.writeFailed }
        guard restored.unresolved == 0 else { throw RedactedEditError.unresolved(restored.unresolved) }
        try DetectionRules.validateFileInput(restored.content, limits: .current())
        try write(Data(restored.content.utf8), snapshot: snapshot, filePath: filePath, replace: replace)
        return RedactedEditSummary(linesChanged: changedLines(oldString, newString), redactions: snapshot.view.redactions.count)
    }

    // WO-647@v2: exact UTF-8 byte matches include overlaps and never use Unicode canonical equivalence.
    private static func uniqueRange(of needle: Data, in bytes: Data) throws -> Range<Int> {
        guard !needle.isEmpty else { throw RedactedEditError.notFound }
        var first: Range<Int>?
        var count = 0
        var offset = bytes.startIndex
        while offset < bytes.endIndex, let range = bytes.range(of: needle, in: offset..<bytes.endIndex) {
            count += 1
            first = first ?? range
            offset = range.lowerBound + 1
        }
        guard let first else { throw RedactedEditError.notFound }
        guard count == 1 else { throw RedactedEditError.ambiguous(count) }
        return first
    }

    // WO-647@v2: use the existing MCP read decision and checked store operation on the entire file.
    private static func inspect(filePath: String, store: RedactionStore, config: PastewatchConfig) throws -> Snapshot {
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: filePath)
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  let mode = attributes[.posixPermissions] as? NSNumber else {
                throw RedactedEditError.inspectionFailed
            }
            let bytes = try DetectionRules.readBoundedFileData(atPath: filePath)
            guard let content = String(data: bytes, encoding: .utf8) else { throw RedactedEditError.inspectionFailed }
            let matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: fileExtension(filePath), relativePath: filePath, config: config
            )
            let minimum = Severity(rawValue: config.mcpMinSeverity) ?? .defaultGuardThreshold
            let decision = MCPReadDecision.evaluate(matches: matches, content: content, config: config,
                                                     minimumSeverity: minimum, filePath: filePath)
            let (view, entries) = try decision.redact(content: content, store: store, filePath: filePath)
            // WO-647@v2: the exposed token cannot fingerprint secret values or depend on a line window.
            let token = SHA256.hash(data: Data(view.utf8)).map { String(format: "%02x", $0) }.joined()
            return Snapshot(bytes: bytes, view: RedactedFileView(content: view, viewToken: token, redactions: entries), mode: mode)
        } catch let error as MCPReadRedactionError {
            throw error
        } catch {
            throw RedactedEditError.inspectionFailed
        }
    }

    // WO-647@v2: the complete edited view follows MCP write's agent-controlled authorization before restoration.
    private static func validateEditedView(_ content: String, filePath: String, config: PastewatchConfig) throws {
        let matches: [DetectedMatch]
        do {
            matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: fileExtension(filePath), relativePath: filePath, config: config
            )
        } catch { throw RedactedEditError.inspectionFailed }
        let decision = GuardDecision.evaluate(matches: matches, content: content, config: config,
                                              contentTrust: .agentControlled, minimumSeverity: nil, filePath: filePath)
        let partition = partitionMutationMatches(decision.reportableMatches, site: .mcpWrite, minAdvisorySeverity: .low)
        if !partition.authorized.isEmpty {
            throw RedactedEditError.plaintextSecrets(partition.authorized.map { "\($0.displayName) at line \($0.line)" }.sorted())
        }
    }

    // WO-647@v2: dotenv aliases use the same format classification as MCP read/write.
    private static func fileExtension(_ path: String) -> String {
        let url = URL(fileURLWithPath: path)
        return DotenvClassifier.isDotenvFile(url.lastPathComponent) ? "env" : url.pathExtension.lowercased()
    }

    // WO-647@v2: windows operate on redacted UTF-8 lines while edits always inspect the whole source.
    private static func selectLines(_ content: String, startLine: Int?, lineCount: Int?) throws -> String {
        guard startLine != nil || lineCount != nil else { return content }
        let start = startLine ?? 1
        guard start > 0, lineCount.map({ $0 > 0 }) ?? true else { throw RedactedEditError.invalidLineRange }
        let bytes = Data(content.utf8)
        var boundaries = [bytes.startIndex]
        for index in bytes.indices where bytes[index] == newlineByte && index + 1 < bytes.endIndex {
            boundaries.append(index + 1)
        }
        guard start <= boundaries.count else { return "" }
        let upperLine = lineCount.map { start - 1 + min($0, boundaries.count - start + 1) } ?? boundaries.count
        let upper = upperLine < boundaries.count ? boundaries[upperLine] : bytes.endIndex
        guard let text = String(data: bytes[boundaries[start - 1]..<upper], encoding: .utf8) else {
            throw RedactedEditError.inspectionFailed
        }
        return text
    }

    // WO-647@v2: ignore unchanged context when counting the edited lines.
    private static func changedLines(_ old: String, _ new: String) -> Int {
        var left = old.split(separator: "\n", omittingEmptySubsequences: false)
        var right = new.split(separator: "\n", omittingEmptySubsequences: false)
        while !left.isEmpty, !right.isEmpty, left.first == right.first { left.removeFirst(); right.removeFirst() }
        while !left.isEmpty, !right.isEmpty, left.last == right.last { left.removeLast(); right.removeLast() }
        return max(left.count, right.count)
    }

    // WO-647@v2: stage with private permissions, preserve the target mode, and rename only after a final byte check.
    private static func write(
        _ bytes: Data, snapshot: Snapshot, filePath: String, replace: (URL, URL) throws -> Void
    ) throws {
        let target = URL(fileURLWithPath: filePath)
        let temporary = target.deletingLastPathComponent().appendingPathComponent(".pastewatch-edit-" + UUID().uuidString)
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw RedactedEditError.writeFailed }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: temporary) }
        do {
            try handle.write(contentsOf: bytes)
            try handle.synchronize()
            try FileManager.default.setAttributes([.posixPermissions: snapshot.mode], ofItemAtPath: temporary.path)
            guard try DetectionRules.readBoundedFileData(atPath: filePath) == snapshot.bytes else {
                throw RedactedEditError.changedSinceRead
            }
            try replace(temporary, target)
        } catch let error as RedactedEditError { throw error } catch { throw RedactedEditError.writeFailed }
    }

    // WO-647@v2: POSIX rename atomically replaces an existing file on both supported platforms.
    private static func atomicReplace(_ source: URL, _ target: URL) throws {
        guard rename(source.path, target.path) == 0 else { throw RedactedEditError.writeFailed }
    }
}
