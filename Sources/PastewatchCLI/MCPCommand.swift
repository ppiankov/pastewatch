import ArgumentParser
import Foundation
import PastewatchCore

// WO-603@v3: POSIX reads return available pipe bytes without waiting to fill the buffer.
#if os(Linux)
import Glibc
#else
import Darwin
#endif

struct MCP: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run as MCP server (stdio transport)"
    )

    @Option(name: .long, help: "Path to audit log file (append mode)")
    var auditLog: String?

    @Option(name: .long, help: "Default minimum severity for redacted reads (critical, high, medium, low)")
    var minSeverity: String?

    func run() throws {
        // WO-574@v4: MCP must fail before serving when active policy is invalid.
        let config = try requireValidatedConfig()
        let logger = auditLog.map { MCPAuditLogger(path: $0) }
        let server = MCPServer(
            auditLogger: logger,
            defaultMinSeverity: minSeverity,
            config: config
        )
        server.start()
    }
}

// WO-603@v2: transport framing is bounded before JSON decoding allocates a request.
private enum MCPInputRecord {
    case line(Data)
    case oversized
}

// WO-597@v2: payload selection resolves before any target-file mutation.
private enum MCPWritePayload {
    case content(String)
    case error(String)
}

// WO-627@v2: validate optional ranges without changing ordinary full-file reads.
private struct MCPReadRange {
    // WO-627@v2: defer conversion until clamping to EOF so large offsets cannot overflow.
    let offset: Double
    // WO-627@v2: lengths are bounded by the existing file-read cap before allocation.
    let length: Int

    // WO-627@v2: only explicitly requested ranges change the response encoding.
    init?(arguments: [String: JSONValue]) throws {
        guard arguments["byte_offset"] != nil || arguments["byte_length"] != nil else { return nil }
        if let value = arguments["byte_offset"] {
            guard case .number(let number) = value,
                  number.isFinite, number >= 0, number.rounded(.towardZero) == number else {
                throw NSError(domain: "MCPReadRange", code: 1, userInfo: [
                    NSLocalizedDescriptionKey: "Invalid byte_offset: expected a non-negative integer"
                ])
            }
            offset = number
        } else {
            offset = 0
        }
        let cap = ScanInputLimits.current().maximumFileBytes
        if let value = arguments["byte_length"] {
            guard case .number(let number) = value,
                  number.isFinite, number > 0, number.rounded(.towardZero) == number else {
                throw NSError(domain: "MCPReadRange", code: 2, userInfo: [
                    NSLocalizedDescriptionKey: "Invalid byte_length: expected a positive integer"
                ])
            }
            length = number >= Double(cap) ? cap : Int(number)
        } else {
            length = cap
        }
    }
}

// WO-630@v2: line windows address the redacted text and preserve its original newline bytes.
private struct MCPLineReadRange {
    let start: Double // WO-630@v2: defer integer conversion until clamping to the file's line count.
    let count: Double? // WO-630@v2: an omitted count reads through EOF without an arbitrary limit.

    // WO-630@v2: reject malformed or mixed range modes before reading or scanning a file.
    init?(arguments: [String: JSONValue]) throws {
        guard arguments["start_line"] != nil || arguments["line_count"] != nil else { return nil }
        guard arguments["byte_offset"] == nil, arguments["byte_length"] == nil else {
            throw NSError(domain: "MCPLineReadRange", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Line ranges and byte ranges are mutually exclusive"
            ])
        }
        start = try Self.positiveInteger(arguments["start_line"], name: "start_line") ?? 1
        count = try Self.positiveInteger(arguments["line_count"], name: "line_count")
    }

    // WO-630@v2: values are positive whole numbers; booleans and null never coerce to integers.
    private static func positiveInteger(_ value: JSONValue?, name: String) throws -> Double? {
        guard let value else { return nil }
        guard case .number(let number) = value,
              number.isFinite, number > 0, number.rounded(.towardZero) == number else {
            throw NSError(domain: "MCPLineReadRange", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "Invalid \(name): expected a positive integer"
            ])
        }
        return number
    }

    // WO-630@v2: split only after mutation so a window cannot expose part of a spanning secret.
    func apply(to content: String, payload: inout [String: JSONValue]) throws {
        let bytes = Data(content.utf8)
        var total = 0
        for byte in bytes where byte == 0x0A { total += 1 }
        if let last = bytes.last, last != 0x0A { total += 1 }
        let first = start - 1 >= Double(total) ? total : Int(start - 1)
        let requested = count ?? Double(total - first)
        let returned = requested >= Double(total - first) ? total - first : Int(requested)
        let range = byteRange(in: bytes, first: first, count: returned)
        guard let text = String(data: bytes.subdata(in: range), encoding: .utf8) else {
            throw CocoaError(.coderInvalidValue)
        }
        payload["content"] = .string(text)
        payload["start_line"] = .number(start)
        payload["line_count"] = .number(Double(returned))
        payload["total_lines"] = .number(Double(total))
        payload["has_more"] = .bool(first + returned < total)
    }

    // WO-630@v2: keep auxiliary memory constant even when a file contains millions of short lines.
    private func byteRange(in bytes: Data, first: Int, count: Int) -> Range<Data.Index> {
        guard count > 0 else { return bytes.endIndex..<bytes.endIndex }
        var line = 0
        var lower = first == 0 ? bytes.startIndex : bytes.endIndex
        for index in bytes.indices where bytes[index] == 0x0A {
            line += 1
            if line == first { lower = index + 1 }
            if line == first + count { return lower..<(index + 1) }
        }
        return lower..<bytes.endIndex
    }
}

// WO-603@v3: retain bounded framing while allowing live request/response exchanges.
private struct MCPLineReader {
    private static let readChunkBytes = 64 * 1_024

    private let handle: FileHandle
    private let maximumLineBytes: Int
    private var buffer = Data()
    private var reachedEOF = false
    private var discardingOversizedLine = false

    init(handle: FileHandle, maximumLineBytes: Int) {
        self.handle = handle
        self.maximumLineBytes = maximumLineBytes
    }

    // WO-603@v3: dispatch complete lines before waiting for additional transport bytes.
    mutating func next() throws -> MCPInputRecord? {
        while true {
            if let newlineIndex = buffer.firstIndex(of: 0x0A) {
                let line = Data(buffer[..<newlineIndex])
                buffer.removeSubrange(buffer.startIndex...newlineIndex)
                return record(for: line)
            }

            if reachedEOF {
                if discardingOversizedLine {
                    discardingOversizedLine = false
                    return .oversized
                }
                guard !buffer.isEmpty else { return nil }
                let line = buffer
                buffer.removeAll(keepingCapacity: true)
                return record(for: line)
            }

            // WO-603@v3: a short pipe read must not wait for the next request or EOF.
            let chunk = try readAvailableChunk()
            if chunk.isEmpty {
                reachedEOF = true
                continue
            }

            if discardingOversizedLine {
                guard let newlineIndex = chunk.firstIndex(of: 0x0A) else { continue }
                discardingOversizedLine = false
                let remainderStart = chunk.index(after: newlineIndex)
                if remainderStart < chunk.endIndex {
                    buffer.append(chunk[remainderStart...])
                }
                return .oversized
            }

            buffer.append(chunk)
            let probeLimit = maximumLineBytes == Int.max
                ? Int.max
                : maximumLineBytes + 1
            if buffer.firstIndex(of: 0x0A) == nil, buffer.count > probeLimit {
                buffer.removeAll(keepingCapacity: true)
                discardingOversizedLine = true
            }
        }
    }

    // WO-603@v3: preserve the fixed allocation cap and retry interrupted reads, not successful short reads.
    private func readAvailableChunk() throws -> Data {
        var chunk = Data(count: Self.readChunkBytes)
        while true {
            let count = chunk.withUnsafeMutableBytes { bytes in
                read(handle.fileDescriptor, bytes.baseAddress, bytes.count)
            }
            if count >= 0 {
                chunk.count = count
                return chunk
            }
            let readError = errno
            guard readError == EINTR else {
                throw POSIXError(POSIXErrorCode(rawValue: readError) ?? .EIO)
            }
        }
    }

    private func record(for rawLine: Data) -> MCPInputRecord {
        var line = rawLine
        if line.last == 0x0D {
            line.removeLast()
        }
        guard line.count <= maximumLineBytes else { return .oversized }
        return .line(line)
    }
}

/// Stateful MCP server that holds redaction mappings for the session.
final class MCPServer {
    // WO-597@v2: reject the unsupported transport marker that caused a destructive overwrite.
    private static let fileReferenceSentinelRegex = try? NSRegularExpression(
        pattern: #"^\s*@@FILE:[^\r\n]+@@\s*$"#
    )
    private let store: RedactionStore
    private let auditLogger: MCPAuditLogger?
    private let defaultMinSeverity: String?
    private let modelRedactionNotice: String // WO-522@v3: fixed to the session placeholder format.
    private let config: PastewatchConfig // WO-574@v4: validated once, immutable for the session.

    init(
        auditLogger: MCPAuditLogger? = nil,
        defaultMinSeverity: String? = nil,
        config: PastewatchConfig = .defaultConfig
    ) {
        self.store = RedactionStore(placeholderPrefix: config.placeholderPrefix)
        self.auditLogger = auditLogger
        self.defaultMinSeverity = defaultMinSeverity
        self.config = config
        let placeholderExample = config.placeholderPrefix.map {
            Obfuscator.makeCustomPlaceholder(prefix: $0, number: 1)
        } ?? "__PW_TYPE_n__"
        self.modelRedactionNotice = RedactionFlowMode.mcpRestorable.modelNotice(
            placeholderExample: placeholderExample
        )
    }

    func start() {
        FileHandle.standardError.write(Data("pastewatch-cli: MCP server started\n".utf8))

        // WO-603@v2: avoid Swift readLine materializing an unbounded agent request.
        var reader = MCPLineReader(
            handle: .standardInput,
            maximumLineBytes: ScanInputLimits.current().maximumLineBytes
        )
        while true {
            let record: MCPInputRecord
            do {
                guard let nextRecord = try reader.next() else { break }
                record = nextRecord
            } catch {
                // WO-603@v2: a transport read failure is terminal, not a parse-error loop.
                FileHandle.standardError.write(
                    Data("pastewatch-cli: MCP transport read failed\n".utf8)
                )
                break
            }

            let response: JSONRPCResponse?
            switch record {
            case .line(let data):
                guard !data.isEmpty else { continue }
                do {
                    let request = try JSONDecoder().decode(JSONRPCRequest.self, from: data)
                    response = handleRequest(request)
                } catch {
                    response = JSONRPCResponse(
                        jsonrpc: "2.0", id: nil,
                        result: nil,
                        error: JSONRPCError(code: -32700, message: "Parse error")
                    )
                }
            case .oversized:
                response = JSONRPCResponse(
                    jsonrpc: "2.0", id: nil,
                    result: nil,
                    error: JSONRPCError(code: -32700, message: "Parse error")
                )
            }

            guard let response else { continue }

            let encoder = JSONEncoder()
            if let responseData = try? encoder.encode(response),
               let responseStr = String(data: responseData, encoding: .utf8) {
                print(responseStr)
                fflush(stdout)
            }
        }
    }

    // MARK: - Request dispatch

    private func handleRequest(_ request: JSONRPCRequest) -> JSONRPCResponse? {
        switch request.method {
        case "initialize":
            return initializeResponse(id: request.id)
        case "notifications/initialized":
            return nil
        case "tools/list":
            return toolsListResponse(id: request.id)
        case "tools/call":
            return toolsCallResponse(id: request.id, params: request.params)
        default:
            if request.method.hasPrefix("notifications/") {
                return nil
            }
            return JSONRPCResponse(
                jsonrpc: "2.0", id: request.id,
                result: nil,
                error: JSONRPCError(code: -32601, message: "Method not found: \(request.method)")
            )
        }
    }

    // MARK: - Handlers

    private func initializeResponse(id: JSONRPCId?) -> JSONRPCResponse {
        let result: JSONValue = .object([
            "protocolVersion": .string("2024-11-05"),
            "capabilities": .object([
                "tools": .object([:])
            ]),
            "serverInfo": .object([
                "name": .string("pastewatch-cli"),
                "version": .string(AppVersion.current)
            ])
        ])
        return JSONRPCResponse(jsonrpc: "2.0", id: id, result: result, error: nil)
    }

    // WO-630@v2: advertise mutually exclusive text line windows beside existing byte windows.
    // WO-647@v2: expose partial edits beside the whole-file read/write surface.
    private func toolsListResponse(id: JSONRPCId?) -> JSONRPCResponse {
        let tools: JSONValue = .object([
            "tools": .array([
                .object([
                    "name": .string("pastewatch_scan"),
                    "description": .string("Scan text for sensitive data patterns"),
                    "inputSchema": .object([
                        "type": .string("object"),
                        "properties": .object([
                            "text": .object([
                                "type": .string("string"),
                                "description": .string("Text content to scan")
                            ])
                        ]),
                        "required": .array([.string("text")])
                    ])
                ]),
                .object([
                    "name": .string("pastewatch_scan_file"),
                    "description": .string("Scan a file for sensitive data patterns"),
                    "inputSchema": .object([
                        "type": .string("object"),
                        "properties": .object([
                            "path": .object([
                                "type": .string("string"),
                                "description": .string("File path to scan")
                            ])
                        ]),
                        "required": .array([.string("path")])
                    ])
                ]),
                .object([
                    "name": .string("pastewatch_scan_dir"),
                    "description": .string("Scan a directory recursively for sensitive data patterns"),
                    "inputSchema": .object([
                        "type": .string("object"),
                        "properties": .object([
                            "path": .object([
                                "type": .string("string"),
                                "description": .string("Directory path to scan")
                            ])
                        ]),
                        "required": .array([.string("path")])
                    ])
                ]),
                .object([
                    "name": .string("pastewatch_read_file"),
                    "description": .string("Read a file with sensitive values replaced by placeholders. Secrets stay local — only placeholders reach the AI. Use pastewatch_write_file to write back with originals restored."),
                    "inputSchema": .object([
                        "type": .string("object"),
                        "properties": .object([
                            "path": .object([
                                "type": .string("string"),
                                "description": .string("File path to read")
                            ]),
                            // WO-627@v2: callers can reconstruct redacted bytes without Unicode realignment.
                            "byte_offset": .object([
                                "type": .string("integer"),
                                "minimum": .number(0),
                                "description": .string("Zero-based offset in redacted output bytes (default 0). With either byte range argument, content is Base64 with encoding=base64, total_bytes, byte_offset, byte_length and has_more. Decode and concatenate windows before UTF-8 decoding; continue at byte_offset + byte_length.")
                            ]),
                            "byte_length": .object([
                                "type": .string("integer"),
                                "minimum": .number(1),
                                "description": .string("Maximum redacted bytes to return, capped at the existing file-read limit (also the default). Omit both byte arguments for the unchanged plain-text response.")
                            ]),
                            // WO-630@v2: text line windows are an alternative, never a raw-file bypass.
                            "start_line": .object([
                                "type": .string("integer"), "minimum": .number(1),
                                "description": .string("One-based first line in redacted text (default 1). Line windows return plain text, start_line, line_count, total_lines and has_more. Mutually exclusive with byte ranges.")
                            ]),
                            "line_count": .object([
                                "type": .string("integer"), "minimum": .number(1),
                                "description": .string("Maximum redacted lines to return; default through EOF. The whole file is scanned and redacted before slicing; clamp at EOF.")
                            ]),
                            "min_severity": .object([
                                "type": .string("string"),
                                // WO-584@v2: schema text and enum derive from Severity ownership.
                                "description": .string(
                                    "Minimum severity to redact: " +
                                        Severity.allCases.map(\.rawValue).joined(separator: ", ") +
                                        " (default: \(Severity.defaultGuardThreshold.rawValue))"
                                ),
                                "enum": .array(Severity.allCases.map {
                                    .string($0.rawValue)
                                })
                            ])
                        ]),
                        "required": .array([.string("path")])
                    ])
                ]),
                .object([
                    "name": .string("pastewatch_write_file"),
                    "description": .string("Write file contents, resolving any placeholders back to original values locally. Pair with pastewatch_read_file for safe round-trip editing."),
                    "inputSchema": .object([
                        "type": .string("object"),
                        "properties": .object([
                            "path": .object([
                                "type": .string("string"),
                                "description": .string("File path to write")
                            ]),
                            "content": .object([
                                "type": .string("string"),
                                "description": .string("File content (may contain placeholders from pastewatch_read_file)")
                            ]),
                            "contentPath": .object([
                                "type": .string("string"),
                                "description": .string(
                                    "Local UTF-8 payload file; mutually exclusive with content"
                                )
                            ])
                        ]),
                        "required": .array([.string("path")]),
                        "oneOf": .array([
                            .object(["required": .array([.string("content")])]),
                            .object(["required": .array([.string("contentPath")])])
                        ])
                    ])
                ]),
                // WO-647@v2: required edit arguments describe one byte-literal replacement, not a whole-file payload.
                .object([
                    "name": .string("pastewatch_edit_file"),
                    "description": .string("Replace one unique occurrence in a redacted file view, restoring whole placeholders locally. Prefer this tool for small edits; partial placeholders and new plaintext secrets are refused."),
                    "inputSchema": .object([
                        "type": .string("object"),
                        "properties": .object([
                            "path": .object(["type": .string("string"), "description": .string("File path to edit")]),
                            "old_string": .object(["type": .string("string"), "description": .string("Exact unique text from the redacted view")]),
                            "new_string": .object(["type": .string("string"), "description": .string("Replacement text; retain complete placeholders")])
                        ]),
                        "required": .array([.string("path"), .string("old_string"), .string("new_string")])
                    ])
                ]),
                .object([
                    "name": .string("pastewatch_check_output"),
                    "description": .string("Check if text contains raw sensitive data. Use before writing or returning code to verify no secrets leak."),
                    "inputSchema": .object([
                        "type": .string("object"),
                        "properties": .object([
                            "text": .object([
                                "type": .string("string"),
                                "description": .string("Text to check for sensitive data")
                            ])
                        ]),
                        "required": .array([.string("text")])
                    ])
                ])
            ])
        ])
        return JSONRPCResponse(jsonrpc: "2.0", id: id, result: tools, error: nil)
    }

    // WO-647@v2: route partial edits through the shared engine and session-local mappings.
    private func toolsCallResponse(id: JSONRPCId?, params: JSONValue?) -> JSONRPCResponse {
        guard case .object(let paramsDict) = params,
              case .string(let toolName) = paramsDict["name"] else {
            return JSONRPCResponse(
                jsonrpc: "2.0", id: id, result: nil,
                error: JSONRPCError(code: -32602, message: "Invalid params: missing tool name")
            )
        }

        let arguments: [String: JSONValue]
        if case .object(let args) = paramsDict["arguments"] {
            arguments = args
        } else {
            arguments = [:]
        }

        switch toolName {
        case "pastewatch_scan":
            return handleScanText(id: id, arguments: arguments, config: config)
        case "pastewatch_scan_file":
            return handleScanFile(id: id, arguments: arguments, config: config)
        case "pastewatch_scan_dir":
            return handleScanDir(id: id, arguments: arguments, config: config)
        // WO-549@v2: MCP file dispatch preserves the guarded read/write policy.
        case "pastewatch_read_file":
            return handleReadFile(id: id, arguments: arguments, config: config)
        case "pastewatch_write_file":
            return handleWriteFile(id: id, arguments: arguments, config: config)
        // WO-647@v2: edits reuse the same store populated by preceding MCP reads.
        case "pastewatch_edit_file":
            return handleEditFile(id: id, arguments: arguments, config: config)
        case "pastewatch_check_output":
            return handleCheckOutput(id: id, arguments: arguments, config: config)
        default:
            return JSONRPCResponse(
                jsonrpc: "2.0", id: id, result: nil,
                error: JSONRPCError(code: -32602, message: "Unknown tool: \(toolName)")
            )
        }
    }

    // MARK: - Scan tools (existing)

    // WO-550@v2: MCP text scans fail closed when shared detector configuration is invalid.
    private func handleScanText(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let text) = arguments["text"] else {
            return errorResult(id: id, text: "Missing required parameter: text")
        }

        let scanResult = DetectionRules.scanFileIOResult(text, config: config)
        if scanResult.hasSharedPatternErrors {
            auditLogger?.log("SCAN  (inline)  shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed.")
        }
        // WO-577@v3: agent-controlled text cannot authorize its own inline suppression.
        let matches = GuardDecision.evaluate(
            matches: scanResult.matches,
            content: text,
            config: config,
            contentTrust: .agentControlled,
            minimumSeverity: nil,
            // WO-635: inline MCP text has no file-based policy exception.
            filePath: nil
        ).reportableMatches
        auditLogger?.log("SCAN  (inline)  findings=\(matches.count)")
        return successResult(id: id, matches: matches)
    }

    // WO-595@v2: file scans surface bounded-input failures instead of skipping evidence.
    private func handleScanFile(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        guard FileManager.default.fileExists(atPath: path) else {
            return errorResult(id: id, text: "File not found: \(path)")
        }

        let content: String
        do {
            // WO-595@v2: refuse before allocating an oversized MCP scan payload.
            let data = try DetectionRules.readBoundedFileData(atPath: path)
            guard let decoded = String(data: data, encoding: .utf8) else {
                return errorResult(id: id, text: "Could not read file: \(path)")
            }
            content = decoded
        } catch let error as ScanInputLimitError {
            return errorResult(id: id, text: "Scan limit exceeded: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Could not inspect file: \(path)")
        }

        let ext: String
        if DotenvClassifier.isDotenvFile(URL(fileURLWithPath: path).lastPathComponent) {
            ext = "env"
        } else {
            ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        }

        let matches: [DetectedMatch]
        do {
            // WO-129: MCP file scans must use the same shared-pattern-aware file IO path as reads.
            matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content,
                ext: ext,
                relativePath: path,
                config: config
            )
        } catch let error as ScanInputLimitError {
            auditLogger?.log("SCAN  \(path)  input-limit")
            return errorResult(id: id, text: "Scan limit exceeded: \(error.localizedDescription)")
        } catch let error as SharedSecretPatternLoadError {
            auditLogger?.log("SCAN  \(path)  shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Scan error: \(error.localizedDescription)")
        }

        // WO-577@v3: file diagnostics share test, inline, and config allow policy.
        let reportable = GuardDecision.evaluate(
            matches: matches,
            content: content,
            config: config,
            contentTrust: .trustedFile,
            minimumSeverity: nil,
            // WO-635: file diagnostics retain the requested path.
            filePath: path
        ).reportableMatches
        auditLogger?.log("SCAN  \(path)  findings=\(reportable.count)")
        return successResult(id: id, matches: reportable, filePath: path)
    }

    // WO-662@v3: directory diagnostics report scan coverage independently of findings.
    private func handleScanDir(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        guard FileManager.default.fileExists(atPath: path) else {
            return errorResult(id: id, text: "Directory not found: \(path)")
        }

        do {
            // WO-662@v3: clean files are included in the scan count, not in the findings list.
            let report = try DirectoryScanner.scanWithStatistics(directory: path, config: config)
            let fileResults = report.files
            // WO-577@v3: directory diagnostics apply the same policy per trusted file.
            let reportableResults = fileResults.compactMap { result -> FileScanResult? in
                let matches = GuardDecision.evaluate(
                    matches: result.matches,
                    content: result.content,
                    config: config,
                    contentTrust: .trustedFile,
                    minimumSeverity: nil,
                    // WO-635: apply the same path-based policy per directory result.
                    filePath: result.filePath
                ).reportableMatches
                guard !matches.isEmpty else { return nil }
                return FileScanResult(
                    filePath: result.filePath,
                    matches: matches,
                    content: result.content,
                    gitignored: result.gitignored
                )
            }
            let allMatches = reportableResults.flatMap { $0.matches }
            // WO-662@v3: findings-only result length is not the number of files inspected.
            let filesScanned = report.statistics.filesScanned
            let totalFindings = allMatches.count

            var findingsArray: [JSONValue] = []
            for fr in reportableResults {
                for match in fr.matches {
                    findingsArray.append(.object([
                        "type": .string(match.displayName),
                        "severity": .string(match.effectiveSeverity.rawValue),
                        "file": .string(fr.filePath),
                        "line": .number(Double(match.line))
                    ]))
                }
            }

            auditLogger?.log("SCAN  \(path)  files=\(filesScanned) findings=\(totalFindings)")
            // WO-662@v3: disclose skipped files and explicitly qualify a zero-scan result.
            let resultText = report.statistics.summary(findings: totalFindings)

            let content: JSONValue = .array([
                .object([
                    "type": .string("text"),
                    "text": .string(resultText)
                ]),
                .object([
                    "type": .string("text"),
                    "text": .string(encodeJSON(.array(findingsArray)))
                ])
            ])

            return JSONRPCResponse(
                jsonrpc: "2.0", id: id,
                result: .object(["content": content]),
                error: nil
            )
        } catch let error as ScanInputLimitError {
            auditLogger?.log("SCAN  \(path)  input-limit")
            return errorResult(id: id, text: "Scan limit exceeded: \(error.localizedDescription)")
        } catch let error as SharedSecretPatternLoadError {
            auditLogger?.log("SCAN  \(path)  shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Scan error: \(error.localizedDescription)")
        }
    }

    // MARK: - Redacted read/write tools

    // WO-630@v2: verify all authorized replacements and encoding before exposing any file content.
    // WO-637: share the read decision without changing ranges, payloads or audit output.
    // WO-549@v2: MCP reads use the same format-aware guard decision as protected file reads.
    // WO-627@v2: validate range inputs before work; apply them only to the final redacted payload.
    private func handleReadFile(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        // WO-627@v2: invalid range arguments must not silently fall back to an unbounded response.
        let readRange: MCPReadRange?
        // WO-630@v2: line and byte range validation precedes file access.
        let lineRange: MCPLineReadRange?
        do {
            // WO-630@v2: mutually exclusive ranges cannot silently select one mode.
            lineRange = try MCPLineReadRange(arguments: arguments)
            readRange = try MCPReadRange(arguments: arguments)
        } catch {
            return errorResult(id: id, text: error.localizedDescription)
        }

        guard FileManager.default.fileExists(atPath: path) else {
            return errorResult(id: id, text: "File not found: \(path)")
        }

        let content: String
        do {
            // WO-595@v2: MCP redacted reads share the same pre-allocation file cap.
            let data = try DetectionRules.readBoundedFileData(atPath: path)
            guard let decoded = String(data: data, encoding: .utf8) else {
                return errorResult(id: id, text: "Could not read file: \(path)")
            }
            content = decoded
        } catch let error as ScanInputLimitError {
            return errorResult(id: id, text: "Read limit exceeded: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Could not inspect file: \(path)")
        }

        // Precedence: per-request > CLI flag > config > default (high)
        let minSeverity: Severity
        if case .string(let severityStr) = arguments["min_severity"],
           let parsed = Severity(rawValue: severityStr) {
            minSeverity = parsed
        } else if let flagStr = defaultMinSeverity, let parsed = Severity(rawValue: flagStr) {
            minSeverity = parsed
        } else {
            minSeverity = Severity(rawValue: config.mcpMinSeverity) ?? .defaultGuardThreshold
        }

        let ext = DotenvClassifier.isDotenvFile(URL(fileURLWithPath: path).lastPathComponent)
            ? "env"
            : URL(fileURLWithPath: path).pathExtension.lowercased()
        let fileMatches: [DetectedMatch]
        do {
            fileMatches = try DirectoryScanner.scanFileContentOrThrow(
                content: content,
                ext: ext,
                relativePath: path,
                config: config
            )
        } catch let error as ScanInputLimitError {
            auditLogger?.log("READ  \(path)  input-limit")
            return errorResult(id: id, text: "Read limit exceeded: \(error.localizedDescription)")
        } catch let error as SharedSecretPatternLoadError {
            auditLogger?.log("READ  \(path)  shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Scan error: \(error.localizedDescription)")
        }

        // WO-637: the extracted decision preserves WO-549 filtering and WO-635 doc advisories.
        let decision = MCPReadDecision.evaluate(
            matches: fileMatches,
            content: content,
            config: config,
            minimumSeverity: minSeverity,
            filePath: path
        )
        let reportedAdvisories = decision.reportedAdvisories
        let advisories: [JSONValue] = reportedAdvisories.map { match in
            .object([
                "type": .string(match.displayName),
                "severity": .string(match.effectiveSeverity.rawValue),
                "line": .number(Double(match.line))
            ])
        }

        // WO-630@v2: the shared responder cannot forward an unapplied or unencoded read.
        let (response, entries) = decision.response(request: (id: id, filePath: path), content: content, store: store, encode: { redacted, entries in
            let redactions: [JSONValue] = entries.map { entry in
                .object([
                    "type": .string(entry.type), "severity": .string(entry.severity),
                    "line": .number(Double(entry.line)), "placeholder": .string(entry.placeholder)
                ])
            }
            var metadata: [String: JSONValue] = [
                "redactions": .array(redactions), "advisories": .array(advisories),
                "clean": .bool(entries.isEmpty && reportedAdvisories.isEmpty)
            ]
            if !entries.isEmpty { metadata["pastewatch_note"] = .string(modelRedactionNotice) }
            return try encodeReadPayload(content: redacted, range: readRange, lineRange: lineRange,
                                         metadata: metadata, decision: decision)
        }, onFailure: { errorResult(id: id, text: $0) })
        // WO-630@v2: failed reads have no success notice or apparent redaction count.
        if case .object(let result) = response.result, result["isError"] == .bool(true) {
            let failure = MCPReadRedactionError(matches: decision.authorized).localizedDescription
            auditLogger?.log("READ  \(path)  refused \(failure)")
        } else if entries.isEmpty {
            let suffix = reportedAdvisories.isEmpty ? "clean" : "advisory=\(reportedAdvisories.count)"
            auditLogger?.log("READ  \(path)  \(suffix)")
        } else {
            logReadRedactions(entries, path: path, config: config)
        }
        return response
    }

    // WO-630@v2: success notices must follow verified redaction and successful payload encoding.
    private func logReadRedactions(_ entries: [RedactionEntry], path: String, config: PastewatchConfig) {
        let typeNames = Set(entries.map { $0.type }).sorted()
        auditLogger?.log("READ  \(path)  redacted=\(entries.count) [\(typeNames.joined(separator: ", "))]")
        // WO-521: the opt-in notice contains metadata only and remains visible without an audit file.
        if config.operatorRedactionNotices {
            let notice = "[PASTEWATCH] MCP REDACTED \(entries.count) secret(s) [\(typeNames.joined(separator: ", "))]"
            if let auditLogger { auditLogger.log(notice) } else {
                FileHandle.standardError.write(Data("\(notice)\n".utf8))
            }
        }
    }

    // WO-630@v2: preserve unranged fields while line windows use text and byte windows remain Base64.
    private func encodeReadPayload(
        content: String, range: MCPReadRange?, lineRange: MCPLineReadRange?,
        metadata: [String: JSONValue], decision: MCPReadDecision
    ) throws -> String {
        var payload = metadata
        if let range {
            let bytes = Data(content.utf8)
            let start = range.offset >= Double(bytes.count) ? bytes.count : Int(range.offset)
            let length = min(range.length, bytes.count - start)
            payload["content"] = .string(bytes.subdata(in: start..<(start + length)).base64EncodedString())
            payload["encoding"] = .string("base64")
            payload["total_bytes"] = .number(Double(bytes.count))
            payload["byte_offset"] = .number(range.offset)
            payload["byte_length"] = .number(Double(length))
            payload["has_more"] = .bool(start + length < bytes.count)
        } else if let lineRange {
            // WO-630@v2: the line slicer receives only the fully redacted string.
            try lineRange.apply(to: content, payload: &payload)
        } else {
            payload["content"] = .string(content)
        }
        // WO-630@v2: never mask an encoding failure with an apparently successful empty array.
        return try decision.encodePayload(.object(payload))
    }

    // WO-549@v2: MCP writes reject agent-authored plaintext before restoring placeholders.
    private func handleWriteFile(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        let content: String
        switch resolveWritePayload(arguments: arguments, targetPath: path) {
        case .content(let resolvedContent):
            content = resolvedContent
        case .error(let message):
            return errorResult(id: id, text: message)
        }

        let ext = DotenvClassifier.isDotenvFile(URL(fileURLWithPath: path).lastPathComponent)
            ? "env"
            : URL(fileURLWithPath: path).pathExtension.lowercased()
        let writeScan: [DetectedMatch]
        do {
            // WO-549@v2: inspect agent-authored plaintext before restoring placeholders.
            writeScan = try DirectoryScanner.scanFileContentOrThrow(
                content: content,
                ext: ext,
                relativePath: path,
                config: config
            )
        } catch let error as SharedSecretPatternLoadError {
            auditLogger?.log("WRITE \(path)  shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Scan error: \(error.localizedDescription)")
        }
        let writeDecision = GuardDecision.evaluate(
            matches: writeScan,
            content: content,
            config: config,
            contentTrust: .agentControlled,
            minimumSeverity: nil,
            // WO-635: write policy follows the target file path, not the source of its content.
            filePath: path
        )
        let writePartition = partitionMutationMatches(
            writeDecision.reportableMatches,
            site: .mcpWrite,
            minAdvisorySeverity: .low
        )
        if !writePartition.authorized.isEmpty {
            let types = Set(writePartition.authorized.map { $0.displayName }).sorted()
            auditLogger?.log(
                "WRITE \(path)  blocked-plaintext=\(writePartition.authorized.count) " +
                    "[\(types.joined(separator: ", "))]"
            )
            return errorResult(
                id: id,
                text: "Write blocked: content contains \(writePartition.authorized.count) plaintext secret(s). " +
                    "Use placeholders returned by pastewatch_read_file."
            )
        }

        // Resolve placeholders using all file mappings (agent may move values between files).
        let resolved = store.resolveAll(content: content)

        do {
            try resolved.content.write(toFile: path, atomically: true, encoding: .utf8)
        } catch {
            return errorResult(id: id, text: "Could not write file: \(error.localizedDescription)")
        }

        auditLogger?.log("WRITE \(path)  resolved=\(resolved.resolved) unresolved=\(resolved.unresolved)")

        var responseObj: [String: JSONValue] = [
            "written": .bool(true),
            "path": .string(path),
            "resolved": .number(Double(resolved.resolved)),
            "unresolved": .number(Double(resolved.unresolved))
        ]

        if !resolved.unresolvedPlaceholders.isEmpty {
            responseObj["unresolvedPlaceholders"] = .array(resolved.unresolvedPlaceholders.map { .string($0) })
        }

        if !writePartition.advisory.isEmpty {
            responseObj["plaintextSecretWarnings"] = .number(Double(writePartition.advisory.count))
        }

        let result: JSONValue = .array([
            .object([
                "type": .string("text"),
                "text": .string(encodeJSON(.object(responseObj)))
            ])
        ])

        return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object(["content": result]), error: nil)
    }

    // WO-647@v2: the MCP handler delegates all edit decisions and returns metadata only.
    private func handleEditFile(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"],
              case .string(let oldString) = arguments["old_string"],
              case .string(let newString) = arguments["new_string"] else {
            return errorResult(id: id, text: "Missing required parameters: path, old_string, new_string")
        }
        do {
            let summary = try RedactedEdit.edit(filePath: path, oldString: oldString, newString: newString,
                                                store: store, config: config)
            auditLogger?.log("EDIT  lines=\(summary.linesChanged) redactions=\(summary.redactions)")
            let payload: JSONValue = .object([
                "edited": .bool(true), "linesChanged": .number(Double(summary.linesChanged)),
                "redactions": .number(Double(summary.redactions))
            ])
            return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object([
                "content": .array([.object(["type": .string("text"), "text": .string(encodeJSON(payload))])])
            ]), error: nil)
        } catch let error as RedactedEditError {
            return errorResult(id: id, text: error.localizedDescription)
        } catch let error as MCPReadRedactionError {
            return errorResult(id: id, text: error.localizedDescription)
        } catch {
            return errorResult(id: id, text: "Edit refused: inspection or replacement failed")
        }
    }

    // WO-597@v2: one resolver owns mutually exclusive inline and local-file payloads.
    private func resolveWritePayload(
        arguments: [String: JSONValue],
        targetPath: String
    ) -> MCPWritePayload {
        let inlineContent: String?
        if case .string(let value) = arguments["content"] {
            inlineContent = value
        } else {
            inlineContent = nil
        }
        let contentPath: String?
        if case .string(let value) = arguments["contentPath"] {
            contentPath = value
        } else {
            contentPath = nil
        }
        guard (inlineContent == nil) != (contentPath == nil) else {
            return .error("Provide exactly one payload source: content or contentPath")
        }

        if let inlineContent {
            guard !Self.isFileReferenceSentinel(inlineContent) else {
                auditLogger?.log("WRITE \(targetPath)  rejected-file-reference-sentinel")
                return .error("Unsupported file-reference marker; use contentPath")
            }
            return .content(inlineContent)
        }

        guard let contentPath else {
            return .error("Missing payload source")
        }
        let payloadURL = URL(fileURLWithPath: contentPath)
        guard let values = try? payloadURL.resourceValues(forKeys: [.isRegularFileKey]),
              values.isRegularFile == true else {
            return .error("contentPath must name a regular file")
        }
        do {
            let data = try DetectionRules.readBoundedFileData(atPath: contentPath)
            guard let decoded = String(data: data, encoding: .utf8) else {
                throw CocoaError(.fileReadInapplicableStringEncoding)
            }
            return .content(decoded)
        } catch {
            return .error("Could not read contentPath: \(error.localizedDescription)")
        }
    }

    // WO-597@v2: recognize only the unsupported marker shape from the data-loss incident.
    private static func isFileReferenceSentinel(_ content: String) -> Bool {
        guard let regex = fileReferenceSentinelRegex else { return false }
        let range = NSRange(content.startIndex..., in: content)
        return regex.firstMatch(in: content, options: [], range: range)?.range == range
    }

    // WO-550@v2: MCP output checks fail closed on invalid shared detector configuration.
    private func handleCheckOutput(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let text) = arguments["text"] else {
            return errorResult(id: id, text: "Missing required parameter: text")
        }

        let scanResult = DetectionRules.scanFileIOResult(text, config: config)
        if scanResult.hasSharedPatternErrors {
            auditLogger?.log("CHECK (inline) shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed.")
        }
        // WO-577@v3: output supplied by an agent cannot self-authorize inline suppression.
        let matches = GuardDecision.evaluate(
            matches: scanResult.matches,
            content: text,
            config: config,
            contentTrust: .agentControlled,
            minimumSeverity: nil,
            // WO-635: arbitrary model output is pathless, so existing enforcement is retained.
            filePath: nil
        ).reportableMatches
        auditLogger?.log("CHECK (inline)  clean=\(matches.isEmpty)")

        var findingsArray: [JSONValue] = []
        for match in matches {
            findingsArray.append(.object([
                "type": .string(match.displayName),
                "severity": .string(match.effectiveSeverity.rawValue),
                "line": .number(Double(match.line))
            ]))
        }

        let result: JSONValue = .array([
            .object([
                "type": .string("text"),
                "text": .string(encodeJSON(.object([
                    "clean": .bool(matches.isEmpty),
                    "findings": .array(findingsArray)
                ])))
            ])
        ])

        return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object(["content": result]), error: nil)
    }

    // MARK: - Result helpers

    private func successResult(id: JSONRPCId?, matches: [DetectedMatch], filePath: String? = nil) -> JSONRPCResponse {
        var findingsArray: [JSONValue] = []
        for match in matches {
            var entry: [String: JSONValue] = [
                "type": .string(match.displayName),
                // WO-577@v3: diagnostic responses expose evidence, never secret bytes.
                "severity": .string(match.effectiveSeverity.rawValue),
                "line": .number(Double(match.line))
            ]
            if let fp = filePath ?? match.filePath {
                entry["file"] = .string(fp)
            }
            findingsArray.append(.object(entry))
        }

        let summary = matches.isEmpty
            ? "No sensitive data found."
            : "Found \(matches.count) finding(s)."

        let content: JSONValue = .array([
            .object([
                "type": .string("text"),
                "text": .string(summary)
            ]),
            .object([
                "type": .string("text"),
                "text": .string(encodeJSON(.array(findingsArray)))
            ])
        ])

        return JSONRPCResponse(
            jsonrpc: "2.0", id: id,
            result: .object(["content": content]),
            error: nil
        )
    }

    private func errorResult(id: JSONRPCId?, text: String) -> JSONRPCResponse {
        let content: JSONValue = .array([
            .object([
                "type": .string("text"),
                "text": .string(text)
            ])
        ])
        return JSONRPCResponse(
            jsonrpc: "2.0", id: id,
            result: .object([
                "content": content,
                "isError": .bool(true)
            ]),
            error: nil
        )
    }

    private func encodeJSON(_ value: JSONValue) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(value),
              let str = String(data: data, encoding: .utf8) else {
            return "[]"
        }
        return str
    }
}
