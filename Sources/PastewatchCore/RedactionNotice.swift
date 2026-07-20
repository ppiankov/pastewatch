// WO-521: keep model-facing marker semantics consistent across proxy and MCP flows.
public enum RedactionFlowMode {
    case proxyOneWay
    case mcpRestorable

    // WO-522@v3: every caller must supply the marker format used in its flow.
    public func modelNotice(placeholderExample: String) -> String {
        let directionality: String
        switch self {
        case .proxyOneWay:
            directionality = "Proxy mode is one-way: original values are not restored. "
        case .mcpRestorable:
            directionality = "MCP mode is two-way: pastewatch_write_file restores original values locally. "
        }
        return "Markers like \(placeholderExample) are redacted secrets, not corruption. " +
            directionality +
            "Flag a malformed marker or mangled surrounding bytes as possible corruption."
    }
}
