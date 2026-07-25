import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// WO-509: one protocol-aware transformer is shared by Darwin and Linux streaming relays.
struct ToolCallStreamRedactor {
    struct ProcessResult {
        let frames: [SSEFrameRedactionResult]
        let terminateStream: Bool
    }

    private struct Fragment {
        let group: String
        let value: String
        let rawValueRange: Range<Int>
        let encodedValue: Data
    }

    private enum JSONStringKind {
        case key
        case value
    }

    private struct JSONStringValue {
        let path: [String]
        let value: String
        let rawValueRange: Range<Int>
        let kind: JSONStringKind
    }

    private struct PendingFrame {
        let frame: SSEFrameParser.Frame
        let fragments: [Fragment]
    }

    private struct LogicalReplacement {
        let range: Range<Int>
        let value: Data
    }

    private struct LogicalMatch {
        let range: Range<Int>
        let match: DetectedMatch
        let requiresJSONStringLiteral: Bool
    }

    private struct ToolGroupScan {
        let replacements: [LogicalReplacement]
        let mutated: [DetectedMatch]
        let advisory: [DetectedMatch]
    }

    // WO-509: typed failures keep client diagnostics aligned with the fail-closed cause.
    private enum BlockingFailure {
        case toolBufferOverflow
        case parserOverflow
        case toolByteMapping
        case invalidJSONAfterMutation

        var decision: String {
            switch self {
            case .toolBufferOverflow: "blocked_tool_buffer_overflow"
            case .parserOverflow: "blocked_parser_overflow"
            case .toolByteMapping: "blocked_tool_byte_mapping_failure"
            case .invalidJSONAfterMutation: "blocked_invalid_json_after_mutation"
            }
        }

        var errorFrame: Data {
            switch self {
            case .toolBufferOverflow, .parserOverflow:
                ToolCallStreamRedactor.overflowErrorFrame
            case .toolByteMapping, .invalidJSONAfterMutation:
                ToolCallStreamRedactor.mutationSafetyErrorFrame
            }
        }
    }

    private struct FrameStats {
        let count: Int
        let types: [String]
        let advisoryCount: Int
        let advisoryTypes: [String]
        let coverageEvents: [ObfuscationCoverageEvent] // WO-539: tool-call receipt evidence.

        static let empty = FrameStats(
            count: 0,
            types: [],
            advisoryCount: 0,
            advisoryTypes: [],
            coverageEvents: []
        )
    }

    private let config: PastewatchConfig
    private let customRules: [CustomRule]
    private let severity: Severity
    private let debugSink: StreamDebugSink?
    private var pending: [PendingFrame] = []
    private var pendingBytes = 0
    private(set) var peakPendingBytes = 0 // WO-511: deterministic proof that retained frames stay bounded.
    private var activeAnthropicBlocks: Set<Int> = []
    private var activeOpenAIChoices: Set<Int> = []
    private var placeholderCounters: [SensitiveDataType: Int] = [:] // WO-518: stream-wide identity.

    init(
        config: PastewatchConfig,
        customRules: [CustomRule],
        severity: Severity,
        debugSink: StreamDebugSink? = nil
    ) {
        self.config = config
        self.customRules = customRules
        self.severity = severity
        self.debugSink = debugSink
    }

    var hasPendingFrames: Bool { !pending.isEmpty }

    // WO-511: fragments are held until their protocol boundary so split secrets are scanned once.
    mutating func process(_ frame: SSEFrameParser.Frame) -> ProcessResult {
        if frame.data == "[DONE]" {
            let flushed = flushPending()
            guard !flushed.terminateStream else { return flushed }
            return ProcessResult(
                frames: flushed.frames + [record(
                    redactSSEFrame(
                        frame,
                        config: config,
                        severity: severity,
                        customRules: customRules
                    ),
                    frame: frame
                )],
                terminateStream: false
            )
        }

        let fragments = toolFragments(in: frame)
        let stopIndex = anthropicStopIndex(in: frame)
        let openAITerminal = isOpenAITerminal(frame)
        let terminalOpenAIChoices = openAITerminalChoiceIndexes(in: frame)

        if !fragments.isEmpty || !pending.isEmpty {
            // WO-511: reject before retention so one full frame cannot double the aggregate cap.
            guard frame.raw.count <= SSEFrameParser.maxFrameBytes - pendingBytes else {
                return blockPending(.toolBufferOverflow, additionalInputs: [frame.raw])
            }
            pending.append(PendingFrame(frame: frame, fragments: fragments))
            pendingBytes += frame.raw.count
            peakPendingBytes = max(peakPendingBytes, pendingBytes)
            for fragment in fragments where fragment.group.hasPrefix("anthropic:") {
                if let index = Int(fragment.group.dropFirst("anthropic:".count)) {
                    activeAnthropicBlocks.insert(index)
                }
            }
            for fragment in fragments where fragment.group.hasPrefix("openai:") {
                let components = fragment.group.split(separator: ":")
                if components.count > 1, let index = Int(components[1]) {
                    activeOpenAIChoices.insert(index)
                }
            }
            if let stopIndex { activeAnthropicBlocks.remove(stopIndex) }
            activeOpenAIChoices.subtract(terminalOpenAIChoices)

            if (openAITerminal && activeOpenAIChoices.isEmpty)
                || (stopIndex != nil && activeAnthropicBlocks.isEmpty) {
                return flushPending()
            }
            return ProcessResult(frames: [], terminateStream: false)
        }

        let redaction = redactSSEFrame(
            frame,
            config: config,
            severity: severity,
            customRules: customRules
        )
        // WO-509: valid upstream JSON must never become syntactically corrupted downstream.
        guard Self.frameMutationPreservesJSON(redaction.data, original: frame) else {
            return blockPending(.invalidJSONAfterMutation, additionalInputs: [frame.raw])
        }
        return ProcessResult(frames: [record(redaction, frame: frame)], terminateStream: false)
    }

    // WO-511: EOF is a protocol boundary; buffered arguments are scanned before release.
    mutating func finish() -> ProcessResult {
        flushPending()
    }

    // WO-511: parser overflow cannot leapfrog a buffered tool payload.
    mutating func blockForParserOverflow(_ overflow: Data) -> ProcessResult? {
        let containsSSEData = overflow.starts(with: Data("data:".utf8))
            || overflow.range(of: Data("\ndata:".utf8)) != nil
        guard hasPendingFrames || containsSSEData else { return nil }
        return blockPending(.parserOverflow, additionalInputs: [overflow])
    }

    private mutating func blockPending(
        _ failure: BlockingFailure,
        additionalInputs: [Data] = []
    ) -> ProcessResult {
        let inputs = pending.map(\.frame.raw) + additionalInputs
        pending.removeAll(keepingCapacity: false)
        pendingBytes = 0
        activeAnthropicBlocks.removeAll()
        activeOpenAIChoices.removeAll()
        let error = SSEFrameRedactionResult(data: failure.errorFrame, count: 0, types: [])
        debugSink?.record(
            inputs: inputs,
            output: error.data,
            decision: failure.decision,
            shape: "stream-buffer-overflow",
            scannedFields: ["partial_json", "function.arguments"],
            matchTypes: []
        )
        return ProcessResult(frames: [error], terminateStream: true)
    }

    // WO-510: mutate only JSON string-token bytes; surrounding SSE and JSON bytes remain unchanged.
    private mutating func flushPending() -> ProcessResult {
        guard !pending.isEmpty else { return ProcessResult(frames: [], terminateStream: false) }
        var replacementsByFrame: [Int: [(Range<Int>, Data)]] = [:]
        var statsByFrame: [Int: FrameStats] = [:]
        var debugTypesByFrame: [Int: [String]] = [:]

        let groups = Dictionary(grouping: pending.enumerated().flatMap { frameIndex, item in
            item.fragments.map { (frameIndex: frameIndex, fragment: $0) }
        }, by: { $0.fragment.group })
        // WO-518: dictionary order cannot decide placeholder identity across tool groups.
        let orderedGroups = groups.values.sorted { lhs, rhs in
            let left = lhs.map { ($0.frameIndex, $0.fragment.rawValueRange.lowerBound) }.min { $0 < $1 }
            let right = rhs.map { ($0.frameIndex, $0.fragment.rawValueRange.lowerBound) }.min { $0 < $1 }
            return left ?? (Int.max, Int.max) < right ?? (Int.max, Int.max)
        }
        for entries in orderedGroups {
            let originalFragments = entries.map { $0.fragment.value }
            let text = originalFragments.joined()
            guard let scan = scanToolGroup(text, counters: &placeholderCounters) else {
                return blockPending(.toolByteMapping)
            }
            guard let replacements = Self.rewriteFragments(
                entries,
                in: text,
                replacements: scan.replacements
            ) else {
                return blockPending(.toolByteMapping)
            }
            for (frameIndex, frameReplacements) in replacements {
                replacementsByFrame[frameIndex, default: []].append(contentsOf: frameReplacements)
            }
            let debugTypes = scan.mutated.map { "Tool argument: \($0.displayName)" }
                + scan.advisory.map { "Tool argument: \($0.displayName)" }
            for frameIndex in Set(entries.map(\.frameIndex)) {
                debugTypesByFrame[frameIndex, default: []].append(contentsOf: debugTypes)
            }
            if let first = entries.first {
                let toolTypes = scan.mutated.map { "Tool argument: \($0.displayName)" }
                let existing = statsByFrame[first.frameIndex] ?? .empty
                statsByFrame[first.frameIndex] = FrameStats(
                    count: existing.count + scan.mutated.count,
                    types: existing.types + toolTypes,
                    advisoryCount: existing.advisoryCount + scan.advisory.count,
                    advisoryTypes: existing.advisoryTypes
                        + scan.advisory.map { "Tool argument: \($0.displayName)" },
                    coverageEvents: existing.coverageEvents
                        + DetectionRules.obfuscationCoverageEvents(
                            in: text,
                            config: config,
                            mutatedMatches: scan.mutated,
                            advisoryMatches: scan.advisory,
                            source: .toolCall
                        )
                )
            }
        }

        let buffered = pending
        var frames: [SSEFrameRedactionResult] = []
        for (index, item) in buffered.enumerated() {
            var output = item.frame.raw
            let replacements = replacementsByFrame[index] ?? []
            let excludedRanges = item.fragments.map { fragment in
                Self.adjustedRange(fragment.rawValueRange, after: replacements)
            }
            for (range, value) in replacements.sorted(by: { $0.0.lowerBound > $1.0.lowerBound }) {
                output.replaceSubrange(range, with: value)
            }
            let stats = statsByFrame[index] ?? .empty
            // WO-509: tool recognition must not narrow the prior whole-frame coverage.
            let frameWide = redactFrameOutsideToolFragments(output, excluding: excludedRanges)
            let result = SSEFrameRedactionResult(
                data: frameWide.data,
                count: stats.count + frameWide.count,
                types: stats.types + frameWide.types,
                advisoryCount: stats.advisoryCount + frameWide.advisoryCount,
                advisoryTypes: stats.advisoryTypes + frameWide.advisoryTypes,
                toolCallRedactionCount: stats.count,
                coverageEvents: stats.coverageEvents + frameWide.coverageEvents
            )
            guard Self.frameMutationPreservesJSON(result.data, original: item.frame) else {
                return blockPending(.invalidJSONAfterMutation)
            }
            frames.append(record(result, frame: item.frame, debugMatchTypes: debugTypesByFrame[index]))
        }
        pending.removeAll(keepingCapacity: true)
        pendingBytes = 0
        activeAnthropicBlocks.removeAll()
        activeOpenAIChoices.removeAll()
        return ProcessResult(frames: frames, terminateStream: false)
    }

    // WO-509: decode complete argument JSON so escaped secret spellings cannot bypass detection.
    private func scanToolGroup(
        _ text: String,
        counters: inout [SensitiveDataType: Int]
    ) -> ToolGroupScan? {
        let rawMatches = scanStreamText(text, config: config, customRules: customRules)
        let rawOutcome = applyAuthorizedMutations(
            to: text,
            matches: rawMatches,
            site: .proxyResponse,
            minAdvisorySeverity: severity
        )
        var advisory = rawOutcome.advisory
        let rawMatchRanges = rawMatches.map { Self.utf8Range(of: $0, in: text) }
        let argumentData = Data(text.utf8)
        let validJSON = (try? JSONSerialization.jsonObject(
            with: argumentData,
            options: [.fragmentsAllowed]
        )) != nil
        // WO-519@v2: complete escaped tokens remain scannable when aggregate JSON is truncated.
        let tokens = Self.jsonStringValues(in: argumentData)
        let tokenRanges = tokens.map(\.rawValueRange)
        var logicalMutations: [LogicalMatch] = []
        for match in rawOutcome.mutated {
            let range = Self.utf8Range(of: match, in: text)
            guard validJSON else {
                logicalMutations.append(LogicalMatch(
                    range: range,
                    match: match,
                    requiresJSONStringLiteral: false
                ))
                continue
            }
            let insideString = tokenRanges.contains { tokenRange in
                tokenRange.lowerBound <= range.lowerBound && range.upperBound <= tokenRange.upperBound
            }
            let replacement = insideString
                ? Self.jsonStringContent("PW_PLACEHOLDER")
                : Self.jsonStringLiteral("PW_PLACEHOLDER")
            guard Self.replacingJSONRange(range, with: replacement, in: text) != nil else { return nil }
            logicalMutations.append(LogicalMatch(
                range: range,
                match: match,
                requiresJSONStringLiteral: !insideString
            ))
        }

        // WO-516: decoded object keys and values are equally capable of carrying secrets.
        for token in tokens {
            let tokenMatches = scanStreamText(token.value, config: config, customRules: customRules)
            let tokenOutcome = applyAuthorizedMutations(
                to: token.value,
                matches: tokenMatches,
                site: .proxyResponse,
                minAdvisorySeverity: severity
            )
            for match in tokenMatches {
                let decodedRange = Self.utf8Range(of: match, in: token.value)
                guard let encodedRange = Self.rawJSONRange(for: decodedRange, in: Self.encodedValue(in: text, token: token)) else {
                    if tokenOutcome.mutated.contains(where: { $0.id == match.id }) { return nil }
                    continue
                }
                let logicalRange = Range(uncheckedBounds: (
                    token.rawValueRange.lowerBound + encodedRange.lowerBound,
                    token.rawValueRange.lowerBound + encodedRange.upperBound
                ))
                guard !rawMatchRanges.contains(where: { Self.rangesOverlap($0, logicalRange) }) else { continue }
                if tokenOutcome.mutated.contains(where: { $0.id == match.id }) {
                    logicalMutations.append(LogicalMatch(
                        range: logicalRange,
                        match: match,
                        requiresJSONStringLiteral: false
                    ))
                } else if tokenOutcome.advisory.contains(where: { $0.id == match.id }) {
                    advisory.append(match)
                }
            }
        }
        // WO-519@v2: an escape outside a complete token is not safe to relay raw.
        guard validJSON || !Self.hasUnmappedJSONEscape(in: argumentData, tokens: tokens) else {
            return nil
        }
        return Self.finalizeToolGroupScan(
            logicalMutations,
            advisory: advisory,
            counters: &counters
        )
    }

    // WO-518: assign ordinals only after raw and decoded matches share one logical order.
    private static func finalizeToolGroupScan(
        _ logicalMutations: [LogicalMatch],
        advisory: [DetectedMatch],
        counters: inout [SensitiveDataType: Int]
    ) -> ToolGroupScan {
        let ordered = logicalMutations.sorted { $0.range.lowerBound < $1.range.lowerBound }
        let replacements = ordered.map { item in
            counters[item.match.type, default: 0] += 1
            let placeholder = Obfuscator.makePlaceholder(
                type: item.match.type,
                number: counters[item.match.type] ?? 1
            )
            return LogicalReplacement(
                range: item.range,
                value: item.requiresJSONStringLiteral
                    ? jsonStringContent("\"\(placeholder)\"")
                    : jsonStringContent(placeholder)
            )
        }
        return ToolGroupScan(
            replacements: replacements,
            mutated: ordered.map(\.match),
            advisory: advisory
        )
    }

    private static func utf8Range(of match: DetectedMatch, in text: String) -> Range<Int> {
        let lowerBound = text[..<match.range.lowerBound].utf8.count
        return lowerBound..<(lowerBound + text[match.range].utf8.count)
    }

    private static func encodedValue(in text: String, token: JSONStringValue) -> Data {
        let data = Data(text.utf8)
        return Data(data[token.rawValueRange])
    }

    private static func rangesOverlap(_ lhs: Range<Int>, _ rhs: Range<Int>) -> Bool {
        lhs.lowerBound < rhs.upperBound && rhs.lowerBound < lhs.upperBound
    }

    // WO-519@v2: malformed JSON is relayed only when every escape was decoded and scanned.
    private static func hasUnmappedJSONEscape(in data: Data, tokens: [JSONStringValue]) -> Bool {
        let mappedRanges = tokens.map(\.rawValueRange)
        return data.indices.contains { index in
            data[index] == 0x5C && !mappedRanges.contains(where: { $0.contains(index) })
        }
    }

    // WO-509: post-mutation validation turns raw fallback corruption into a local fail-closed event.
    private static func frameMutationPreservesJSON(
        _ output: Data,
        original frame: SSEFrameParser.Frame
    ) -> Bool {
        guard let originalPayload = frame.data,
              (try? JSONSerialization.jsonObject(
                with: Data(originalPayload.utf8),
                options: [.fragmentsAllowed]
              )) != nil else { return true }
        var parser = SSEFrameParser()
        let parsed = parser.feed(output)
        guard !parsed.overflowFlushed,
              parsed.frames.count == 1,
              let outputPayload = parsed.frames.first?.data else { return false }
        return (try? JSONSerialization.jsonObject(
            with: Data(outputPayload.utf8),
            options: [.fragmentsAllowed]
        )) != nil
    }

    // WO-510: structural-spanning custom matches fail closed instead of corrupting tool JSON.
    private static func replacingJSONRange(
        _ range: Range<Int>,
        with replacement: Data,
        in text: String
    ) -> Data? {
        var candidate = Data(text.utf8)
        candidate.replaceSubrange(range, with: replacement)
        guard (try? JSONSerialization.jsonObject(with: candidate, options: [.fragmentsAllowed])) != nil else {
            return nil
        }
        return candidate
    }

    private static func adjustedRange(
        _ original: Range<Int>,
        after replacements: [(Range<Int>, Data)]
    ) -> Range<Int> {
        func adjusted(_ bound: Int) -> Int {
            bound + replacements.reduce(into: 0) { delta, replacement in
                guard replacement.0.upperBound <= bound else { return }
                delta += replacement.1.count - replacement.0.count
            }
        }
        return adjusted(original.lowerBound)..<adjusted(original.upperBound)
    }

    // WO-509 and WO-512: scan sibling fields without counting tool-token matches a second time.
    private func redactFrameOutsideToolFragments(
        _ raw: Data,
        excluding excludedRanges: [Range<Int>]
    ) -> SSEFrameRedactionResult {
        guard !excludedRanges.isEmpty, let text = String(data: raw, encoding: .utf8) else {
            return redactRawStreamBytes(
                raw,
                config: config,
                severity: severity,
                customRules: customRules
            )
        }
        let matches = scanStreamText(text, config: config, customRules: customRules).filter { match in
            let lowerBound = text[..<match.range.lowerBound].utf8.count
            let upperBound = lowerBound + text[match.range].utf8.count
            return !excludedRanges.contains { range in
                lowerBound < range.upperBound && upperBound > range.lowerBound
            }
        }
        let outcome = applyAuthorizedMutations(
            to: text,
            matches: matches,
            site: .proxyResponse,
            minAdvisorySeverity: severity
        )
        return SSEFrameRedactionResult(
            data: outcome.mutated.isEmpty ? raw : Data(outcome.text.utf8),
            count: outcome.mutated.count,
            types: outcome.mutated.map(\.displayName),
            advisoryCount: outcome.advisory.count,
            advisoryTypes: outcome.advisory.map(\.displayName),
            coverageEvents: DetectionRules.obfuscationCoverageEvents(
                in: text,
                config: config,
                mutatedMatches: outcome.mutated,
                advisoryMatches: outcome.advisory,
                source: .response
            )
        )
    }

    // WO-510: map decoded match spans back to raw token bytes across fragment boundaries.
    private static func rewriteFragments(
        _ entries: [(frameIndex: Int, fragment: Fragment)],
        in text: String,
        replacements logicalReplacements: [LogicalReplacement]
    ) -> [Int: [(Range<Int>, Data)]]? {
        guard !logicalReplacements.isEmpty else { return [:] }
        let sorted = logicalReplacements.sorted { $0.range.lowerBound < $1.range.lowerBound }
        var fragmentStarts: [Int] = []
        var nextStart = 0
        for entry in entries {
            fragmentStarts.append(nextStart)
            nextStart += entry.fragment.value.utf8.count
        }

        var replacements: [Int: [(Range<Int>, Data)]] = [:]
        for replacement in sorted {
            let matchStart = replacement.range.lowerBound
            let matchEnd = replacement.range.upperBound
            var insertedPlaceholder = false
            var coveredBytes = 0

            for (entry, fragmentStart) in zip(entries, fragmentStarts) {
                let fragmentEnd = fragmentStart + entry.fragment.value.utf8.count
                let overlapStart = max(matchStart, fragmentStart)
                let overlapEnd = min(matchEnd, fragmentEnd)
                guard overlapStart < overlapEnd else { continue }
                let localRange = (overlapStart - fragmentStart)..<(overlapEnd - fragmentStart)
                guard let encodedRange = rawJSONRange(
                    for: localRange,
                    in: entry.fragment.encodedValue
                ) else { return nil }
                let rawRange = Range(uncheckedBounds: (
                    entry.fragment.rawValueRange.lowerBound + encodedRange.lowerBound,
                    entry.fragment.rawValueRange.lowerBound + encodedRange.upperBound
                ))
                let value = insertedPlaceholder ? Data() : replacement.value
                replacements[entry.frameIndex, default: []].append((rawRange, value))
                insertedPlaceholder = true
                coveredBytes += overlapEnd - overlapStart
            }
            guard insertedPlaceholder, coveredBytes == matchEnd - matchStart else { return nil }
        }
        return replacements
    }

    private static func rawJSONRange(for decodedRange: Range<Int>, in encoded: Data) -> Range<Int>? {
        var rawCursor = 0
        var decodedCursor = 0
        var rawLowerBound: Int? = decodedRange.lowerBound == 0 ? 0 : nil
        var rawUpperBound: Int? = decodedRange.upperBound == 0 ? 0 : nil

        while rawCursor < encoded.count {
            let segmentStart = rawCursor
            let segmentEnd: Int
            if encoded[rawCursor] == 0x5C {
                guard rawCursor + 1 < encoded.count else { return nil }
                if encoded[rawCursor + 1] == 0x75 {
                    guard rawCursor + 6 <= encoded.count else { return nil }
                    var candidateEnd = rawCursor + 6
                    if decodeJSONContent(Data(encoded[rawCursor..<candidateEnd])) == nil,
                       candidateEnd + 6 <= encoded.count,
                       encoded[candidateEnd] == 0x5C,
                       encoded[candidateEnd + 1] == 0x75 {
                        candidateEnd += 6
                    }
                    segmentEnd = candidateEnd
                } else {
                    segmentEnd = rawCursor + 2
                }
            } else {
                guard let width = utf8ScalarWidth(encoded[rawCursor]), rawCursor + width <= encoded.count else {
                    return nil
                }
                segmentEnd = rawCursor + width
            }

            guard let decoded = decodeJSONContent(Data(encoded[segmentStart..<segmentEnd])) else { return nil }
            decodedCursor += decoded.utf8.count
            rawCursor = segmentEnd
            if decodedRange.lowerBound == decodedCursor { rawLowerBound = rawCursor }
            if decodedRange.upperBound == decodedCursor { rawUpperBound = rawCursor }
        }
        guard let rawLowerBound, let rawUpperBound else { return nil }
        return rawLowerBound..<rawUpperBound
    }

    private static func decodeJSONContent(_ content: Data) -> String? {
        var token = Data([0x22])
        token.append(content)
        token.append(0x22)
        return decodeJSONString(token)
    }

    private static func utf8ScalarWidth(_ leadingByte: UInt8) -> Int? {
        if leadingByte < 0x80 { return 1 }
        if leadingByte & 0xE0 == 0xC0 { return 2 }
        if leadingByte & 0xF0 == 0xE0 { return 3 }
        if leadingByte & 0xF8 == 0xF0 { return 4 }
        return nil
    }

    private func record(
        _ result: SSEFrameRedactionResult,
        frame: SSEFrameParser.Frame,
        debugMatchTypes: [String]? = nil
    ) -> SSEFrameRedactionResult {
        let decision = result.data != frame.raw ? "mutated" : (result.advisoryCount > 0 ? "advisory" : "unchanged")
        debugSink?.record(
            inputs: [frame.raw],
            output: result.data,
            decision: decision,
            shape: streamShape(frame),
            scannedFields: scannedFields(frame),
            matchTypes: debugMatchTypes ?? (result.types + result.advisoryTypes)
        )
        return result
    }

    private func streamShape(_ frame: SSEFrameParser.Frame) -> String {
        guard let payload = frame.data,
              let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any] else {
            return "unknown"
        }
        if object["delta"] is [String: Any] { return "anthropic-delta" }
        if object["choices"] is [[String: Any]] { return "openai-compatible" }
        return "unknown"
    }

    private func scannedFields(_ frame: SSEFrameParser.Frame) -> [String] {
        let fragments = toolFragments(in: frame)
        if fragments.contains(where: { $0.group.hasPrefix("anthropic:") }) { return ["partial_json"] }
        if fragments.contains(where: { $0.group.hasPrefix("openai:") }) { return ["function.arguments"] }
        guard let payload = frame.data,
              let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any],
              let delta = object["delta"] as? [String: Any] else { return ["raw_frame"] }
        return delta.compactMap { key, value in key == "type" || !(value is String) ? nil : key }.sorted()
    }

    private func toolFragments(in frame: SSEFrameParser.Frame) -> [Fragment] {
        guard let payload = frame.data,
              let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any] else {
            return []
        }

        if let delta = object["delta"] as? [String: Any],
           delta["type"] as? String == "input_json_delta",
           let value = delta["partial_json"] as? String,
           let index = object["index"] as? Int,
           let token = Self.jsonStringValues(in: Data(payload.utf8)).first(where: {
               $0.kind == .value
                   && $0.path.suffix(2) == ["delta", "partial_json"]
                   && $0.value == value
           }),
           let rawRange = Self.rawFrameRange(for: token.rawValueRange, in: frame.raw) {
            return [Fragment(
                group: "anthropic:\(index)",
                value: value,
                rawValueRange: rawRange,
                encodedValue: Data(frame.raw[rawRange])
            )]
        }

        guard let choices = object["choices"] as? [[String: Any]] else { return [] }
        let tokens = Self.jsonStringValues(in: Data(payload.utf8)).filter {
            $0.kind == .value
                && $0.path.suffix(2) == ["function", "arguments"]
                && $0.path.contains("tool_calls")
        }
        var result: [Fragment] = []
        var tokenIndex = 0
        for (fallbackChoiceIndex, choice) in choices.enumerated() {
            guard let delta = choice["delta"] as? [String: Any],
                  let calls = delta["tool_calls"] as? [[String: Any]] else { continue }
            let choiceIndex = choice["index"] as? Int ?? fallbackChoiceIndex
            for (fallbackIndex, call) in calls.enumerated() {
                guard let function = call["function"] as? [String: Any],
                      let value = function["arguments"] as? String,
                      tokenIndex < tokens.count,
                      let rawRange = Self.rawFrameRange(
                        for: tokens[tokenIndex].rawValueRange,
                        in: frame.raw
                      ) else { continue }
                let callIndex = call["index"] as? Int ?? fallbackIndex
                result.append(Fragment(
                    group: "openai:\(choiceIndex):\(callIndex)",
                    value: value,
                    rawValueRange: rawRange,
                    encodedValue: Data(frame.raw[rawRange])
                ))
                tokenIndex += 1
            }
        }
        return result
    }

    private func anthropicStopIndex(in frame: SSEFrameParser.Frame) -> Int? {
        guard let payload = frame.data,
              let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any],
              object["type"] as? String == "content_block_stop" else { return nil }
        return object["index"] as? Int
    }

    private func isOpenAITerminal(_ frame: SSEFrameParser.Frame) -> Bool {
        !openAITerminalChoiceIndexes(in: frame).isEmpty
    }

    private func openAITerminalChoiceIndexes(in frame: SSEFrameParser.Frame) -> Set<Int> {
        guard let payload = frame.data,
              let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any],
              let choices = object["choices"] as? [[String: Any]] else { return [] }
        return Set(choices.enumerated().compactMap { fallbackIndex, choice in
            guard let value = choice["finish_reason"], !(value is NSNull) else { return nil }
            return choice["index"] as? Int ?? fallbackIndex
        })
    }

    // WO-510: record structural paths so unrelated duplicate key names cannot steal a replacement.
    private static func jsonStringValues(in data: Data) -> [JSONStringValue] {
        var values: [JSONStringValue] = []
        var cursor = 0
        parseJSONValue(in: data, cursor: &cursor, path: [], values: &values)
        return values
    }

    private static func parseJSONValue(
        in data: Data,
        cursor: inout Int,
        path: [String],
        values: inout [JSONStringValue]
    ) {
        skipJSONWhitespace(in: data, cursor: &cursor)
        guard cursor < data.count else { return }
        if data[cursor] == 0x7B {
            parseJSONObject(in: data, cursor: &cursor, path: path, values: &values)
        } else if data[cursor] == 0x5B {
            parseJSONArray(in: data, cursor: &cursor, path: path, values: &values)
        } else if data[cursor] == 0x22, let end = jsonStringEnd(in: data, from: cursor) {
            let token = Data(data[cursor...end])
            if let value = decodeJSONString(token) {
                values.append(JSONStringValue(
                    path: path,
                    value: value,
                    rawValueRange: (cursor + 1)..<end,
                    kind: .value
                ))
            }
            cursor = end + 1
        } else {
            while cursor < data.count && ![0x2C, 0x5D, 0x7D].contains(data[cursor]) { cursor += 1 }
        }
    }

    private static func parseJSONObject(
        in data: Data,
        cursor: inout Int,
        path: [String],
        values: inout [JSONStringValue]
    ) {
        cursor += 1
        while cursor < data.count {
            skipJSONWhitespace(in: data, cursor: &cursor)
            guard cursor < data.count, data[cursor] != 0x7D,
                  data[cursor] == 0x22,
                  let keyEnd = jsonStringEnd(in: data, from: cursor),
                  let key = decodeJSONString(Data(data[cursor...keyEnd])) else { break }
            // WO-516: retain key-token bytes so escaped key spellings cannot bypass scanning.
            values.append(JSONStringValue(
                path: path + [key],
                value: key,
                rawValueRange: (cursor + 1)..<keyEnd,
                kind: .key
            ))
            cursor = keyEnd + 1
            skipJSONWhitespace(in: data, cursor: &cursor)
            guard cursor < data.count, data[cursor] == 0x3A else { break }
            cursor += 1
            parseJSONValue(in: data, cursor: &cursor, path: path + [key], values: &values)
            skipJSONWhitespace(in: data, cursor: &cursor)
            if cursor < data.count, data[cursor] == 0x2C { cursor += 1; continue }
            break
        }
        if cursor < data.count, data[cursor] == 0x7D { cursor += 1 }
    }

    private static func parseJSONArray(
        in data: Data,
        cursor: inout Int,
        path: [String],
        values: inout [JSONStringValue]
    ) {
        cursor += 1
        while cursor < data.count {
            skipJSONWhitespace(in: data, cursor: &cursor)
            if cursor < data.count, data[cursor] == 0x5D { cursor += 1; return }
            parseJSONValue(in: data, cursor: &cursor, path: path + ["[]"], values: &values)
            skipJSONWhitespace(in: data, cursor: &cursor)
            if cursor < data.count, data[cursor] == 0x2C { cursor += 1; continue }
            if cursor < data.count, data[cursor] == 0x5D { cursor += 1 }
            return
        }
    }

    private static func skipJSONWhitespace(in data: Data, cursor: inout Int) {
        while cursor < data.count && data[cursor].isJSONWhitespace { cursor += 1 }
    }

    private static func jsonStringEnd(in data: Data, from start: Int) -> Int? {
        var cursor = start + 1
        var escaped = false
        while cursor < data.count {
            let byte = data[cursor]
            if escaped {
                escaped = false
            } else if byte == 0x5C {
                escaped = true
            } else if byte == 0x22 {
                return cursor
            }
            cursor += 1
        }
        return nil
    }

    private static func decodeJSONString(_ token: Data) -> String? {
        var array = Data([0x5B])
        array.append(token)
        array.append(0x5D)
        return (try? JSONSerialization.jsonObject(with: array) as? [String])?.first
    }

    private static func jsonStringContent(_ value: String) -> Data {
        guard let encoded = try? JSONSerialization.data(withJSONObject: [value]), encoded.count >= 4 else {
            return Data(value.utf8)
        }
        return Data(encoded.dropFirst(2).dropLast(2))
    }

    private static func jsonStringLiteral(_ value: String) -> Data {
        guard let encoded = try? JSONSerialization.data(withJSONObject: [value]), encoded.count >= 2 else {
            return Data("\"\(value)\"".utf8)
        }
        return Data(encoded.dropFirst().dropLast())
    }

    // WO-510: map the parser's joined data payload back to one raw `data:` line.
    private static func rawFrameRange(for logicalRange: Range<Int>, in raw: Data) -> Range<Int>? {
        var lineStart = 0
        var logicalStart = 0
        while lineStart < raw.count {
            let newline = raw[lineStart...].firstIndex(of: 0x0A) ?? raw.endIndex
            var lineEnd = newline
            if lineEnd > lineStart, raw[lineEnd - 1] == 0x0D { lineEnd -= 1 }
            let prefix = Data("data:".utf8)
            if lineEnd - lineStart >= prefix.count,
               raw[lineStart..<(lineStart + prefix.count)].elementsEqual(prefix) {
                var contentStart = lineStart + prefix.count
                while contentStart < lineEnd && [0x20, 0x09].contains(raw[contentStart]) { contentStart += 1 }
                var contentEnd = lineEnd
                while contentEnd > contentStart && [0x20, 0x09].contains(raw[contentEnd - 1]) { contentEnd -= 1 }
                let logicalEnd = logicalStart + (contentEnd - contentStart)
                if logicalRange.lowerBound >= logicalStart && logicalRange.upperBound <= logicalEnd {
                    let offset = contentStart - logicalStart
                    return (logicalRange.lowerBound + offset)..<(logicalRange.upperBound + offset)
                }
                logicalStart = logicalEnd + 1
            }
            if newline == raw.endIndex { break }
            lineStart = newline + 1
        }
        return nil
    }

    private static let overflowErrorFrame = Data(
        "event: pastewatch_error\ndata: {\"error\":\"stream buffer limit exceeded\"}\n\ndata: [DONE]\n\n".utf8
    )

    private static let mutationSafetyErrorFrame = Data(
        "event: pastewatch_error\ndata: {\"error\":\"stream redaction could not preserve valid JSON\"}\n\n"
            .appending("data: [DONE]\n\n").utf8
    )
}

private extension UInt8 {
    var isJSONWhitespace: Bool { self == 0x20 || self == 0x09 || self == 0x0A || self == 0x0D }
}

/// WO-514: explicit debug sink records raw local stream evidence only when the CLI supplies a path.
public final class StreamDebugSink {
    public static let maxBytes = 64 * 1024 * 1024 // WO-514: bound opt-in evidence on local disk.
    private let handle: FileHandle // WO-517: pinned no-follow descriptor prevents pathname substitution.
    private let lock = NSLock()
    private var bytesWritten = 0
    private var reachedLimit = false

    public init(path: String) throws {
        // WO-517: validation and open are one syscall; later writes never resolve the path again.
        let descriptor = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw StreamDebugSinkError.cannotCreate(path) }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              fchmod(descriptor, 0o600) == 0 else {
            close(descriptor)
            throw StreamDebugSinkError.cannotCreate(path)
        }
        handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        bytesWritten = Int(info.st_size)
        reachedLimit = bytesWritten >= Self.maxBytes
    }

    // WO-514: append one bounded raw/output decision record to the pinned local descriptor.
    func record(
        inputs: [Data],
        output: Data,
        decision: String,
        shape: String = "unknown",
        scannedFields: [String] = [],
        matchTypes: [String] = []
    ) {
        let object: [String: Any] = [
            "decision": decision,
            "shape": shape,
            "scanned_fields": scannedFields,
            "match_types": matchTypes,
            "input_base64": inputs.map { $0.base64EncodedString() },
            "output_base64": output.base64EncodedString()
        ]
        guard var data = try? JSONSerialization.data(withJSONObject: object) else { return }
        data.append(0x0A)
        lock.lock()
        defer { lock.unlock() }
        guard !reachedLimit else { return }
        guard bytesWritten + data.count <= Self.maxBytes else {
            let marker = Data("{\"decision\":\"dump_limit_reached\"}\n".utf8)
            if bytesWritten + marker.count <= Self.maxBytes {
                if (try? handle.write(contentsOf: marker)) != nil { bytesWritten += marker.count }
            }
            reachedLimit = true
            return
        }
        if (try? handle.write(contentsOf: data)) != nil { bytesWritten += data.count }
    }
}

/// WO-514: expose debug-dump startup failures without revealing captured content.
public enum StreamDebugSinkError: LocalizedError {
    case cannotCreate(String)

    public var errorDescription: String? {
        switch self {
        case .cannotCreate(let path): return "cannot create stream debug dump at \(path)"
        }
    }
}
