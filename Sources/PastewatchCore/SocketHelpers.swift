import Foundation

/// WO-206: shared socket send-all helper used by both the macOS URLSession path
/// (SSEStreamRelay) and the Linux curl path (CurlHTTPClient).
/// Retries until all bytes are written or a hard error (EPIPE / closed socket) occurs.
/// Returns false when a hard error terminates the loop early; true when all bytes are sent.
/// WO-214: EINTR is retried rather than treated as a permanent error, since SIGINT
/// (Ctrl-C) or other signals can interrupt send() without closing the connection.
@discardableResult
func sendAll(_ data: Data, to socket: Int32, flags: Int32) -> Bool {
    var sent = true
    data.withUnsafeBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        var remaining = ptr.count
        var offset = 0
        while remaining > 0 {
            let n = send(socket, base.advanced(by: offset), remaining, flags)
            if n < 0 {
                if errno == EINTR { continue }  // WO-214: signal interruption — retry
                sent = false; break
            }
            if n == 0 { sent = false; break }
            offset += n
            remaining -= n
        }
    }
    return sent
}

/// WO-220: result from shared SSE frame redaction.
struct SSEFrameRedactionResult {
    let data: Data
    let count: Int
    let types: [String]
}

/// WO-220: shared per-SSE-event frame redaction used by both the macOS URLSession path
/// (SSEStreamRelay) and the Linux curl path (CurlHTTPClient).
/// Extracts delta.text from an Anthropic SSE JSON payload, scans for secrets, and
/// re-serializes the frame with obfuscated text. Returns the original frame on any
/// parse failure so secrets are never silently dropped (though they remain in the frame).
/// Accumulates stats only when re-serialization succeeds (mirrors WO-180/WO-188).
func redactSSEFrame(
    _ frame: SSEFrameParser.Frame,
    config: PastewatchConfig,
    severity: Severity
) -> SSEFrameRedactionResult {
    guard let dataPayload = frame.data, dataPayload != "[DONE]" else {
        return SSEFrameRedactionResult(data: frame.raw, count: 0, types: [])
    }
    guard let jsonData = dataPayload.data(using: .utf8),
          let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
          let delta = json["delta"] as? [String: Any],
          let text = delta["text"] as? String else {
        return SSEFrameRedactionResult(data: frame.raw, count: 0, types: [])
    }
    let matches = DetectionRules.scan(text, config: config)
    let filtered = matches.filter { $0.effectiveSeverity >= severity }
    guard !filtered.isEmpty else { return SSEFrameRedactionResult(data: frame.raw, count: 0, types: []) }
    let obfuscated = Obfuscator.obfuscate(text, matches: filtered)
    var modifiedDelta = delta
    modifiedDelta["text"] = obfuscated
    var modifiedJson = json
    modifiedJson["delta"] = modifiedDelta
    guard let resultData = try? JSONSerialization.data(withJSONObject: modifiedJson),
          let resultStr = String(data: resultData, encoding: .utf8) else {
        return SSEFrameRedactionResult(data: frame.raw, count: 0, types: [])
    }
    return SSEFrameRedactionResult(
        data: frame.reserializedWith(data: resultStr),
        count: filtered.count,
        types: filtered.map { $0.displayName }
    )
}
