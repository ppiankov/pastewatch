import ArgumentParser
import Foundation
import PastewatchCore

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

/// Stateful MCP server that holds redaction mappings for the session.
final class MCPServer {
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

        while let line = readLine(strippingNewline: true) {
            guard !line.isEmpty else { continue }
            guard let data = line.data(using: .utf8) else { continue }

            let response: JSONRPCResponse?
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
                            ])
                        ]),
                        "required": .array([.string("path"), .string("content")])
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
            minimumSeverity: nil
        ).reportableMatches
        auditLogger?.log("SCAN  (inline)  findings=\(matches.count)")
        return successResult(id: id, matches: matches)
    }

    private func handleScanFile(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        guard FileManager.default.fileExists(atPath: path) else {
            return errorResult(id: id, text: "File not found: \(path)")
        }

        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return errorResult(id: id, text: "Could not read file: \(path)")
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
            minimumSeverity: nil
        ).reportableMatches
        auditLogger?.log("SCAN  \(path)  findings=\(reportable.count)")
        return successResult(id: id, matches: reportable, filePath: path)
    }

    private func handleScanDir(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        guard FileManager.default.fileExists(atPath: path) else {
            return errorResult(id: id, text: "Directory not found: \(path)")
        }

        do {
            let fileResults = try DirectoryScanner.scan(directory: path, config: config)
            // WO-577@v3: directory diagnostics apply the same policy per trusted file.
            let reportableResults = fileResults.compactMap { result -> FileScanResult? in
                let matches = GuardDecision.evaluate(
                    matches: result.matches,
                    content: result.content,
                    config: config,
                    contentTrust: .trustedFile,
                    minimumSeverity: nil
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
            let filesScanned = fileResults.count
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
            let resultText = "Scanned \(filesScanned) files. Found \(totalFindings) findings."

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
        } catch let error as SharedSecretPatternLoadError {
            auditLogger?.log("SCAN  \(path)  shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Scan error: \(error.localizedDescription)")
        }
    }

    // MARK: - Redacted read/write tools

    // WO-549@v2: MCP reads use the same format-aware guard decision as protected file reads.
    private func handleReadFile(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        guard FileManager.default.fileExists(atPath: path) else {
            return errorResult(id: id, text: "File not found: \(path)")
        }

        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return errorResult(id: id, text: "Could not read file: \(path)")
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
        } catch let error as SharedSecretPatternLoadError {
            auditLogger?.log("READ  \(path)  shared-pattern-error")
            return errorResult(id: id, text: "Shared pattern load failed: \(error.localizedDescription)")
        } catch {
            return errorResult(id: id, text: "Scan error: \(error.localizedDescription)")
        }

        // WO-549@v2: route MCP reads through GuardDecision so test-credential filtering,
        // inline-allow, and config allowlist apply identically to guard-read.
        let decision = GuardDecision.evaluate(
            matches: fileMatches,
            content: content,
            config: config,
            contentTrust: .trustedFile,
            minimumSeverity: minSeverity
        )

        let partition = partitionMutationMatches(
            decision.reportableMatches,
            site: .mcpRead,
            minAdvisorySeverity: minSeverity
        )
        let matches = partition.authorized
        let advisories: [JSONValue] = partition.advisory.map { match in
            .object([
                "type": .string(match.displayName),
                "severity": .string(match.effectiveSeverity.rawValue),
                "line": .number(Double(match.line))
            ])
        }

        if matches.isEmpty {
            let advisorySuffix = partition.advisory.isEmpty
                ? "clean"
                : "advisory=\(partition.advisory.count)"
            auditLogger?.log("READ  \(path)  \(advisorySuffix)")
            let result: JSONValue = .array([
                .object([
                    "type": .string("text"),
                    "text": .string(encodeJSON(.object([
                        "content": .string(content),
                        "redactions": .array([]),
                        "advisories": .array(advisories),
                        "clean": .bool(partition.advisory.isEmpty)
                    ])))
                ])
            ])
            return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object(["content": result]), error: nil)
        }

        let (redacted, entries) = store.redact(content: content, matches: matches, filePath: path)

        let typeNames = Set(entries.map { $0.type }).sorted()
        auditLogger?.log("READ  \(path)  redacted=\(entries.count) [\(typeNames.joined(separator: ", "))]")
        // WO-521: the opt-in notice contains metadata only and remains visible without an audit file.
        if config.operatorRedactionNotices {
            let notice = "[PASTEWATCH] MCP REDACTED \(entries.count) secret(s) " +
                "[\(typeNames.joined(separator: ", "))]"
            if let auditLogger {
                auditLogger.log(notice)
            } else {
                FileHandle.standardError.write(Data("\(notice)\n".utf8))
            }
        }

        var redactionsArray: [JSONValue] = []
        for entry in entries {
            redactionsArray.append(.object([
                "type": .string(entry.type),
                "severity": .string(entry.severity),
                "line": .number(Double(entry.line)),
                "placeholder": .string(entry.placeholder)
            ]))
        }

        let result: JSONValue = .array([
            .object([
                "type": .string("text"),
                "text": .string(encodeJSON(.object([
                    "content": .string(redacted),
                    "redactions": .array(redactionsArray),
                    "advisories": .array(advisories),
                    "clean": .bool(false),
                    // WO-522@v3: explain the session-specific, locally restorable marker.
                    "pastewatch_note": .string(modelRedactionNotice)
                ])))
            ])
        ])

        return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object(["content": result]), error: nil)
    }

    // WO-549@v2: MCP writes reject agent-authored plaintext before restoring placeholders.
    private func handleWriteFile(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        guard case .string(let content) = arguments["content"] else {
            return errorResult(id: id, text: "Missing required parameter: content")
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
            minimumSeverity: nil
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
            minimumSeverity: nil
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
