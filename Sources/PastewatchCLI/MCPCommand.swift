import ArgumentParser
import Foundation
import PastewatchCore

struct MCP: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run as MCP server (stdio transport)"
    )

    func run() throws {
        FileHandle.standardError.write(Data("pastewatch-cli: MCP server started\n".utf8))

        while let line = readLine(strippingNewline: true) {
            guard !line.isEmpty else { continue }
            guard let data = line.data(using: .utf8) else { continue }

            let response: JSONRPCResponse
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

            let encoder = JSONEncoder()
            if let responseData = try? encoder.encode(response),
               let responseStr = String(data: responseData, encoding: .utf8) {
                print(responseStr)
                fflush(stdout)
            }
        }
    }

    // MARK: - Request dispatch

    private func handleRequest(_ request: JSONRPCRequest) -> JSONRPCResponse {
        switch request.method {
        case "initialize":
            return initializeResponse(id: request.id)
        case "notifications/initialized":
            return JSONRPCResponse(jsonrpc: "2.0", id: request.id, result: .object([:]), error: nil)
        case "tools/list":
            return toolsListResponse(id: request.id)
        case "tools/call":
            return toolsCallResponse(id: request.id, params: request.params)
        default:
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
                "version": .string("0.4.0")
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

        let config = PastewatchConfig.defaultConfig

        switch toolName {
        case "pastewatch_scan":
            return handleScanText(id: id, arguments: arguments, config: config)
        case "pastewatch_scan_file":
            return handleScanFile(id: id, arguments: arguments, config: config)
        case "pastewatch_scan_dir":
            return handleScanDir(id: id, arguments: arguments, config: config)
        default:
            return JSONRPCResponse(
                jsonrpc: "2.0", id: id, result: nil,
                error: JSONRPCError(code: -32602, message: "Unknown tool: \(toolName)")
            )
        }
    }

    // MARK: - Tool implementations

    private func handleScanText(id: JSONRPCId?, arguments: [String: JSONValue], config: PastewatchConfig) -> JSONRPCResponse {
        guard case .string(let text) = arguments["text"] else {
            return errorResult(id: id, text: "Missing required parameter: text")
        }

        let matches = DetectionRules.scan(text, config: config)
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
                        line: pv.line, filePath: path, customRuleName: vm.customRuleName
                    ))
                }
            }
        } else {
            matches = DetectionRules.scan(content, config: config)
        }

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
