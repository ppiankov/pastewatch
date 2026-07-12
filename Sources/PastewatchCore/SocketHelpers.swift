import Foundation

/// WO-206: shared socket send-all helper used by both the macOS URLSession path
/// (SSEStreamRelay) and the Linux curl path (CurlHTTPClient).
/// Retries until all bytes are written or a hard error (EPIPE / closed socket) occurs.
/// Returns false when a hard error terminates the loop early; true when all bytes are sent.
/// WO-214: EINTR is retried rather than treated as a permanent error, since SIGINT
/// (Ctrl-C) or other signals can interrupt send() without closing the connection.
@discardableResult
func sendAll(_ data: Data, to socket: Int32, flags: Int32) -> Bool {
    sendAll(data, to: socket, flags: flags) { socket, pointer, length, flags in
        send(socket, pointer, length, flags)
    }
}

/// WO-373: injectable syscall path keeps partial-write and EINTR tests deterministic.
@discardableResult
func sendAll(
    _ data: Data,
    to socket: Int32,
    flags: Int32,
    sendFunction: (Int32, UnsafeRawPointer, Int, Int32) -> Int
) -> Bool {
    var sent = true
    data.withUnsafeBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        var remaining = ptr.count
        var offset = 0
        while remaining > 0 {
            let n = sendFunction(socket, base.advanced(by: offset), remaining, flags)
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
    let redactionCount: Int
    let redactionTypes: [String]
    let advisoryCount: Int
    let advisoryTypes: [String]

    init(
        data: Data,
        count: Int,
        types: [String],
        advisoryCount: Int = 0,
        advisoryTypes: [String] = []
    ) {
        self.data = data
        self.redactionCount = count
        self.redactionTypes = types
        self.advisoryCount = advisoryCount
        self.advisoryTypes = advisoryTypes
    }

    var count: Int { redactionCount }
    var types: [String] { redactionTypes }
}

/// WO-404: mutation is certainty-gated, not severity-gated.
func mutationSafeProxyMatches(_ matches: [DetectedMatch]) -> [DetectedMatch] {
    matches.filter(\.mutationSafe)
}

/// WO-404: --severity controls advisory volume, never mutation.
func streamAdvisoryMatches(_ matches: [DetectedMatch], severity: Severity) -> [DetectedMatch] {
    matches.filter { !$0.mutationSafe && $0.effectiveSeverity >= severity }
}

/// WO-399: include configured custom rules on the streaming response path.
func scanStreamText(_ text: String, config: PastewatchConfig) -> [DetectedMatch] {
    DetectionRules.scan(
        text,
        config: config,
        customRules: CustomRule.compileValid(config.customRules)
    )
}

/// WO-291: raw streaming fallback redaction must not become a strict-UTF-8 bypass.
/// Invalid bytes with no mutation-safe match are forwarded byte-identical; when a
/// mutation-safe ASCII fixture is present, the lossy view is redacted before relay.
func redactRawStreamBytes(
    _ raw: Data,
    config: PastewatchConfig,
    severity: Severity
) -> SSEFrameRedactionResult {
    guard !raw.isEmpty else {
        return SSEFrameRedactionResult(data: raw, count: 0, types: [])
    }
    // swiftlint:disable:next optional_data_string_conversion
    let text = String(data: raw, encoding: .utf8) ?? String(decoding: raw, as: UTF8.self)
    let matches = scanStreamText(text, config: config)
    let filtered = mutationSafeProxyMatches(matches)
    let advisories = streamAdvisoryMatches(matches, severity: severity)
    let advisoryTypes = advisories.map { $0.displayName }
    guard !filtered.isEmpty else {
        return SSEFrameRedactionResult(
            data: raw, count: 0, types: [],
            advisoryCount: advisories.count,
            advisoryTypes: advisoryTypes
        )
    }
    let obfuscated = Obfuscator.obfuscate(text, matches: filtered)
    return SSEFrameRedactionResult(
        data: Data(obfuscated.utf8),
        count: filtered.count,
        types: filtered.map { $0.displayName },
        advisoryCount: advisories.count,
        advisoryTypes: advisoryTypes
    )
}

/// WO-336/WO-337: insert a synthetic alert/advisory frame immediately before
/// the raw SSE `[DONE]` frame while preserving all preceding raw bytes.
func insertingSSEDataBeforeDone(_ inserted: Data?, into data: Data) -> Data {
    guard let inserted, !inserted.isEmpty,
          let frameStart = rawSSEDoneFrameStart(in: data) else {
        return data
    }
    var result = Data()
    result.append(contentsOf: data[..<frameStart])
    result.append(inserted)
    result.append(contentsOf: data[frameStart...])
    return result
}

private func rawSSEDoneFrameStart(in data: Data) -> Data.Index? {
    let doneLine = Data("data: [DONE]".utf8)
    guard let doneRange = data.range(of: doneLine) else { return nil }
    let beforeDone = Data(data[..<doneRange.lowerBound])
    let crlfTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
    let lfTerminator = Data([0x0A, 0x0A])
    let crlfStart = beforeDone.range(of: crlfTerminator, options: .backwards)?.upperBound
    let lfStart = beforeDone.range(of: lfTerminator, options: .backwards)?.upperBound
    let startOffset = max(crlfStart ?? 0, lfStart ?? 0)
    return data.index(data.startIndex, offsetBy: startOffset)
}

/// WO-220: shared per-SSE-event frame redaction used by both the macOS URLSession path
/// (SSEStreamRelay) and the Linux curl path (CurlHTTPClient).
/// Extracts text-bearing string fields from an Anthropic SSE JSON delta, scans for
/// secrets, and re-serializes the frame with obfuscated values. Returns the original
/// frame on any parse failure so secrets are never silently dropped, though they
/// remain in the frame.
/// Accumulates stats only when re-serialization succeeds (mirrors WO-180/WO-188).
func redactSSEFrame(
    _ frame: SSEFrameParser.Frame,
    config: PastewatchConfig,
    severity: Severity
) -> SSEFrameRedactionResult {
    guard let dataPayload = frame.data else {
        return redactRawStreamBytes(frame.raw, config: config, severity: severity)
    }
    guard dataPayload != "[DONE]" else {
        return SSEFrameRedactionResult(data: frame.raw, count: 0, types: [])
    }
    guard let jsonData = dataPayload.data(using: .utf8),
          let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
          let delta = json["delta"] as? [String: Any] else {
        return redactRawStreamBytes(frame.raw, config: config, severity: severity)
    }
    var modifiedDelta = delta
    var redacted = 0
    var types: [String] = []
    var advisoryCount = 0
    var advisoryTypes: [String] = []

    for (field, value) in delta {
        guard field != "type", let text = value as? String else { continue }
        let matches = scanStreamText(text, config: config)
        let filtered = mutationSafeProxyMatches(matches)
        let advisories = streamAdvisoryMatches(matches, severity: severity)
        advisoryCount += advisories.count
        advisoryTypes.append(contentsOf: advisories.map { $0.displayName })
        guard !filtered.isEmpty else { continue }
        // WO-295: redact thinking_delta/input_json_delta and future text-bearing
        // delta string fields, not only text_delta's `text` field.
        modifiedDelta[field] = Obfuscator.obfuscate(text, matches: filtered)
        redacted += filtered.count
        types.append(contentsOf: filtered.map { $0.displayName })
    }

    guard redacted > 0 else {
        return SSEFrameRedactionResult(
            data: frame.raw, count: 0, types: [],
            advisoryCount: advisoryCount, advisoryTypes: advisoryTypes
        )
    }
    var modifiedJson = json
    modifiedJson["delta"] = modifiedDelta
    guard let resultData = try? JSONSerialization.data(withJSONObject: modifiedJson),
          let resultStr = String(data: resultData, encoding: .utf8) else {
        return SSEFrameRedactionResult(
            data: frame.raw, count: 0, types: [],
            advisoryCount: advisoryCount, advisoryTypes: advisoryTypes
        )
    }
    return SSEFrameRedactionResult(
        data: frame.reserializedWith(data: resultStr),
        count: redacted,
        types: types,
        advisoryCount: advisoryCount,
        advisoryTypes: advisoryTypes
    )
}
