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
    let toolCallRedactionCount: Int // WO-512: distinguish tool payload mutation from ordinary text.
    let coverageEvents: [ObfuscationCoverageEvent] // WO-539: stream receipt evidence.

    init(
        data: Data,
        count: Int,
        types: [String],
        advisoryCount: Int = 0,
        advisoryTypes: [String] = [],
        toolCallRedactionCount: Int = 0,
        coverageEvents: [ObfuscationCoverageEvent] = []
    ) {
        self.data = data
        self.redactionCount = count
        self.redactionTypes = types
        self.advisoryCount = advisoryCount
        self.advisoryTypes = advisoryTypes
        self.toolCallRedactionCount = toolCallRedactionCount
        self.coverageEvents = coverageEvents
    }

    var count: Int { redactionCount }
    var types: [String] { redactionTypes }
}

/// WO-454: compatibility filter backed by the evidence partition.
func mutationSafeProxyMatches(_ matches: [DetectedMatch], site: MutationSite) -> [DetectedMatch] {
    partitionMutationMatches(matches, site: site, minAdvisorySeverity: .low).authorized
}

/// WO-454: --severity controls advisory volume, never mutation authorization.
func streamAdvisoryMatches(
    _ matches: [DetectedMatch],
    severity: Severity,
    site: MutationSite
) -> [DetectedMatch] {
    partitionMutationMatches(matches, site: site, minAdvisorySeverity: severity).advisory
}

/// WO-399: include configured custom rules on the streaming response path.
func scanStreamText(
    _ text: String,
    config: PastewatchConfig,
    customRules: [CustomRule]? = nil
) -> [DetectedMatch] {
    DetectionRules.scan(
        text,
        config: config,
        customRules: customRules ?? CustomRule.compileValid(config.customRules)
    )
}

/// WO-291: raw streaming fallback redaction must not become a strict-UTF-8 bypass.
/// Invalid bytes with no mutation-safe match are forwarded byte-identical; when a
/// mutation-safe ASCII fixture is present, the lossy view is redacted before relay.
func redactRawStreamBytes(
    _ raw: Data,
    config: PastewatchConfig,
    severity: Severity,
    customRules: [CustomRule]? = nil
) -> SSEFrameRedactionResult {
    guard !raw.isEmpty else {
        return SSEFrameRedactionResult(data: raw, count: 0, types: [])
    }
    // swiftlint:disable:next optional_data_string_conversion
    let text = String(data: raw, encoding: .utf8) ?? String(decoding: raw, as: UTF8.self)
    let matches = scanStreamText(text, config: config, customRules: customRules)
    let outcome = applyAuthorizedMutations(
        to: text,
        matches: matches,
        site: .proxyResponse,
        minAdvisorySeverity: severity
    )
    let coverageEvents = DetectionRules.obfuscationCoverageEvents(
        in: text,
        config: config,
        mutatedMatches: outcome.mutated,
        advisoryMatches: outcome.advisory,
        source: .response
    )
    let advisoryTypes = outcome.advisory.map { $0.displayName }
    guard !outcome.mutated.isEmpty else {
        return SSEFrameRedactionResult(
            data: raw, count: 0, types: [],
            advisoryCount: outcome.advisory.count,
            advisoryTypes: advisoryTypes,
            coverageEvents: coverageEvents
        )
    }
    return SSEFrameRedactionResult(
        data: Data(outcome.text.utf8),
        count: outcome.mutated.count,
        types: outcome.mutated.map { $0.displayName },
        advisoryCount: outcome.advisory.count,
        advisoryTypes: advisoryTypes,
        coverageEvents: coverageEvents
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

// WO-384: preserve unterminated partial-frame bytes before a DONE alert.
private func rawSSEDoneFrameStart(in data: Data) -> Data.Index? {
    // WO-384: locate insertion without moving partial bytes behind the synthetic frame.
    let doneLine = Data("data: [DONE]".utf8)
    guard let doneRange = data.range(of: doneLine) else { return nil }
    let beforeDone = Data(data[..<doneRange.lowerBound])
    let crlfTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
    let lfTerminator = Data([0x0A, 0x0A])
    let crlfStart = beforeDone.range(of: crlfTerminator, options: .backwards)?.upperBound
    let lfStart = beforeDone.range(of: lfTerminator, options: .backwards)?.upperBound
    guard crlfStart != nil || lfStart != nil else {
        // WO-384: never splice an alert ahead of unterminated partial-frame bytes.
        return doneRange.lowerBound
    }
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
    severity: Severity,
    customRules: [CustomRule]? = nil
) -> SSEFrameRedactionResult {
    guard let dataPayload = frame.data else {
        return redactRawStreamBytes(frame.raw, config: config, severity: severity, customRules: customRules)
    }
    guard dataPayload != "[DONE]" else {
        return SSEFrameRedactionResult(data: frame.raw, count: 0, types: [])
    }
    guard let jsonData = dataPayload.data(using: .utf8),
          let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
          let delta = json["delta"] as? [String: Any] else {
        return redactRawStreamBytes(frame.raw, config: config, severity: severity, customRules: customRules)
    }
    var modifiedDelta = delta
    var redacted = 0
    var types: [String] = []
    var advisoryCount = 0
    var advisoryTypes: [String] = []
    var coverageEvents: [ObfuscationCoverageEvent] = []

    for (field, value) in delta {
        guard field != "type", let text = value as? String else { continue }
        let matches = scanStreamText(text, config: config, customRules: customRules)
        let outcome = applyAuthorizedMutations(
            to: text,
            matches: matches,
            site: .proxyResponse,
            minAdvisorySeverity: severity
        )
        advisoryCount += outcome.advisory.count
        advisoryTypes.append(contentsOf: outcome.advisory.map { $0.displayName })
        coverageEvents.append(contentsOf: DetectionRules.obfuscationCoverageEvents(
            in: text,
            config: config,
            mutatedMatches: outcome.mutated,
            advisoryMatches: outcome.advisory,
            source: .response
        ))
        guard !outcome.mutated.isEmpty else { continue }
        // WO-295: redact thinking_delta/input_json_delta and future text-bearing
        // delta string fields, not only text_delta's `text` field.
        modifiedDelta[field] = outcome.text
        redacted += outcome.mutated.count
        types.append(contentsOf: outcome.mutated.map { $0.displayName })
    }

    guard redacted > 0 else {
        return SSEFrameRedactionResult(
            data: frame.raw, count: 0, types: [],
            advisoryCount: advisoryCount, advisoryTypes: advisoryTypes,
            coverageEvents: coverageEvents
        )
    }
    var modifiedJson = json
    modifiedJson["delta"] = modifiedDelta
    guard let resultData = try? JSONSerialization.data(withJSONObject: modifiedJson),
          let resultStr = String(data: resultData, encoding: .utf8) else {
        return SSEFrameRedactionResult(
            data: frame.raw, count: 0, types: [],
            advisoryCount: advisoryCount, advisoryTypes: advisoryTypes,
            coverageEvents: coverageEvents
        )
    }
    return SSEFrameRedactionResult(
        data: frame.reserializedWith(data: resultStr),
        count: redacted,
        types: types,
        advisoryCount: advisoryCount,
        advisoryTypes: advisoryTypes,
        coverageEvents: coverageEvents
    )
}
