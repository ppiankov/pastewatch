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
        let logger = auditLog.map { MCPAuditLogger(path: $0) }
        let server = MCPServer(auditLogger: logger, defaultMinSeverity: minSeverity)
        server.start()
    }
}

/// Stateful MCP server that holds redaction mappings for the session.
final class MCPServer {
    private let store = RedactionStore()
    private let auditLogger: MCPAuditLogger?
    private let defaultMinSeverity: String?

    init(auditLogger: MCPAuditLogger? = nil, defaultMinSeverity: String? = nil) {
        self.auditLogger = auditLogger
        self.defaultMinSeverity = defaultMinSeverity
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
                "version": .string("0.19.0")
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
                                "description": .string("Minimum severity to redact: critical, high, medium, low (default: high)"),
                                "enum": .array([
                                    .string("critical"),
                                    .string("high"),
                                    .string("medium"),
                                    .string("low")
                                ])
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

        let config = PastewatchConfig.resolve()

        switch toolName {
        case "pastewatch_scan":
            return handleScanText(id: id, arguments: arguments, config: config)
        case "pastewatch_scan_file":
            return handleScanFile(id: id, arguments: arguments, config: config)
        case "pastewatch_scan_dir":
            return handleScanDir(id: id, arguments: arguments, config: config)
        case "pastewatch_read_file":
            return handleReadFile(id: id, arguments: arguments, config: config)
        case "pastewatch_write_file":
            return handleWriteFile(id: id, arguments: arguments)
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

    private func handleScanText(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let text) = arguments["text"] else {
            return errorResult(id: id, text: "Missing required parameter: text")
        }

        let matches = DetectionRules.scan(text, config: config)
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
        if path.hasSuffix(".env") || URL(fileURLWithPath: path).lastPathComponent == ".env" {
            ext = "env"
        } else {
            ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        }

        var matches: [DetectedMatch]
        if let parser = parserForExtension(ext) {
            let parsedValues = parser.parseValues(from: content)
            matches = []
            for pv in parsedValues {
                let valueMatches = DetectionRules.scan(pv.value, config: config)
                for vm in valueMatches {
                    matches.append(DetectedMatch(
                        type: vm.type, value: vm.value, range: vm.range,
                        line: pv.line, filePath: path, customRuleName: vm.customRuleName,
                        customSeverity: vm.customSeverity
                    ))
                }
            }
        } else {
            matches = DetectionRules.scan(content, config: config)
        }

        auditLogger?.log("SCAN  \(path)  findings=\(matches.count)")
        return successResult(id: id, matches: matches, filePath: path)
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
            let allMatches = fileResults.flatMap { $0.matches }
            let filesScanned = fileResults.count
            let totalFindings = allMatches.count

            var findingsArray: [JSONValue] = []
            for fr in fileResults {
                for match in fr.matches {
                    findingsArray.append(.object([
                        "type": .string(match.displayName),
                        "value": .string(match.value),
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
        } catch {
            return errorResult(id: id, text: "Scan error: \(error.localizedDescription)")
        }
    }

    // MARK: - Redacted read/write tools

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
            minSeverity = Severity(rawValue: config.mcpMinSeverity) ?? .high
        }

        let allMatches = DetectionRules.scan(content, config: config)
        let matches = allMatches.filter { $0.effectiveSeverity >= minSeverity }

        if matches.isEmpty {
            auditLogger?.log("READ  \(path)  clean")
            let result: JSONValue = .array([
                .object([
                    "type": .string("text"),
                    "text": .string(encodeJSON(.object([
                        "content": .string(content),
                        "redactions": .array([]),
                        "clean": .bool(true)
                    ])))
                ])
            ])
            return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object(["content": result]), error: nil)
        }

        let (redacted, entries) = store.redact(content: content, matches: matches, filePath: path)

        let typeNames = Set(entries.map { $0.type }).sorted()
        auditLogger?.log("READ  \(path)  redacted=\(entries.count) [\(typeNames.joined(separator: ", "))]")

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
                    "clean": .bool(false)
                ])))
            ])
        ])

        return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object(["content": result]), error: nil)
    }

    private func handleWriteFile(id: JSONRPCId?, arguments: [String: JSONValue]) -> JSONRPCResponse {
        guard case .string(let path) = arguments["path"] else {
            return errorResult(id: id, text: "Missing required parameter: path")
        }

        guard case .string(let content) = arguments["content"] else {
            return errorResult(id: id, text: "Missing required parameter: content")
        }

        // Resolve placeholders using all file mappings (agent may move values between files)
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

        let result: JSONValue = .array([
            .object([
                "type": .string("text"),
                "text": .string(encodeJSON(.object(responseObj)))
            ])
        ])

        return JSONRPCResponse(jsonrpc: "2.0", id: id, result: .object(["content": result]), error: nil)
    }

    private func handleCheckOutput(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let text) = arguments["text"] else {
            return errorResult(id: id, text: "Missing required parameter: text")
        }

        let matches = DetectionRules.scan(text, config: config)
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
                "value": .string(match.value),
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
