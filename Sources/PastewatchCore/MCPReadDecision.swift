import Foundation

// WO-637: MCP and diagnostics share the exact read authorization and advisory selection.
public struct MCPReadDecision {
    public let authorized: [DetectedMatch]
    public let reportedAdvisories: [DetectedMatch]

    // WO-630@v2: keep the read-time placeholder operation coupled to its authorized matches.
    public func redact(content: String, store: RedactionStore, filePath: String) throws -> (String, [RedactionEntry]) {
        do {
            let result = try store.redactChecked(content: content, matches: authorized, filePath: filePath)
            guard result.1.count == authorized.count else { throw CocoaError(.coderInvalidValue) }
            return result
        } catch {
            throw MCPReadRedactionError(matches: authorized)
        }
    }

    // WO-630@v2: encoding errors must not silently substitute a successful empty payload.
    public func encodePayload(_ payload: JSONValue) throws -> String {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            guard let text = String(data: try encoder.encode(payload), encoding: .utf8) else {
                throw CocoaError(.coderInvalidValue)
            }
            return text
        } catch {
            throw MCPReadRedactionError(matches: authorized)
        }
    }

    // WO-630@v2: only a fully validated and encoded read may become an MCP success response.
    public func response(
        request: (id: JSONRPCId?, filePath: String), content: String, store: RedactionStore,
        encode: (String, [RedactionEntry]) throws -> String,
        onFailure: (String) -> JSONRPCResponse
    ) -> (JSONRPCResponse, [RedactionEntry]) {
        do {
            let (redacted, entries) = try redact(content: content, store: store, filePath: request.filePath)
            let text = try encode(redacted, entries)
            let blocks: JSONValue = .array([.object(["type": .string("text"), "text": .string(text)])])
            return (JSONRPCResponse(jsonrpc: "2.0", id: request.id, result: .object(["content": blocks]), error: nil), entries)
        } catch {
            return (onFailure(MCPReadRedactionError(matches: authorized).localizedDescription), [])
        }
    }

    // WO-637: preserve trusted-file filtering and WO-635 advisories below the MCP threshold.
    public static func evaluate(
        matches: [DetectedMatch], content: String, config: PastewatchConfig,
        minimumSeverity: Severity, filePath: String?
    ) -> MCPReadDecision {
        let decision = GuardDecision.evaluate(
            matches: matches, content: content, config: config,
            contentTrust: .trustedFile, minimumSeverity: minimumSeverity, filePath: filePath
        )
        let partition = partitionMutationMatches(
            decision.reportableMatches, site: .mcpRead, minAdvisorySeverity: minimumSeverity
        )
        return MCPReadDecision(
            authorized: partition.authorized,
            reportedAdvisories: partition.advisory + partition.advisoryBelowThreshold.filter {
                $0.advisory == .documentationPolicy
            }
        )
    }
}

// WO-630@v2: failure diagnostics retain only type and line, never values or file content.
public struct MCPReadRedactionError: LocalizedError {
    public let findings: [String] // WO-630@v2: each entry is a type-and-line summary only.

    // WO-630@v2: discard all sensitive match fields before exposing an error to the client.
    public init(matches: [DetectedMatch]) {
        findings = matches.map { "\($0.displayName) at line \($0.line)" }.sorted()
    }

    // WO-630@v2: use the same class-only message for store, range and encoding failures.
    public var errorDescription: String? {
        findings.isEmpty ? "Read refused: could not encode content" :
            "Read refused: redaction failed for " + findings.joined(separator: ", ")
    }
}
