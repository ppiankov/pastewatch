import Foundation

/// Incremental Server-Sent Events frame parser.
/// Feed raw bytes from a streaming upstream; it yields complete SSE frames
/// (terminated by \n\n or \r\n\r\n) and retains the partial remainder for the
/// next chunk. Thread-safe for single-producer use; each ProxyServer connection
/// owns its own parser instance.
public struct SSEFrameParser {
    /// An SSE frame as parsed from the stream.
    public struct Frame {
        /// Raw bytes of the complete SSE frame (including trailing \n\n).
        public let raw: Data
        /// Parsed event type (from "event: <type>" line), nil if absent.
        public let eventType: String?
        /// Parsed data payload (from "data: <value>" line, or "[DONE]" sentinel).
        public let data: String?
    }

    /// Maximum bytes allowed for a single SSE frame before fail-safe truncation.
    /// Prevents unbounded memory growth on a malformed/very large frame.
    public static let maxFrameBytes = 4 * 1024 * 1024 // 4 MB

    private var buffer = Data()

    /// Parse result from `feed(_:)`.
    public struct FeedResult {
        /// Complete frames extracted this call.
        public let frames: [Frame]
        /// True if the buffer exceeded `maxFrameBytes` and was flushed as a raw passthrough.
        public let overflowFlushed: Bool
        /// Raw bytes of overflow content (non-empty only when `overflowFlushed` is true).
        public let overflowBytes: Data
    }

    /// Feed the next chunk of upstream bytes.
    /// Returns complete frames and any overflow condition.
    public mutating func feed(_ chunk: Data) -> FeedResult {
        buffer.append(chunk)

        // Fail-safe: if buffer grows beyond max, flush raw and reset.
        if buffer.count > SSEFrameParser.maxFrameBytes {
            let overflow = buffer
            buffer = Data()
            return FeedResult(frames: [], overflowFlushed: true, overflowBytes: overflow)
        }

        var frames: [Frame] = []

        // WO-291: keep the fast string-domain path for all-UTF-8 buffers, but make the
        // raw fallback parse each complete frame independently. A valid frame followed by
        // invalid UTF-8 must still expose frame.data to redactSSEFrame().
        if let remaining = String(data: buffer, encoding: .utf8) {
            var cursor = remaining.startIndex
            while let (frame, nextCursor) = extractNextFrameFromString(remaining, from: cursor) {
                frames.append(frame)
                cursor = nextCursor
            }
            // WO-309: one tail copy per feed() call, not one full remaining-buffer
            // copy per parsed frame.
            buffer = Data(remaining[cursor...].utf8)
        } else {
            while let (frame, remaining) = extractNextFrameRaw(from: buffer) {
                frames.append(frame)
                buffer = remaining
            }
        }

        return FeedResult(frames: frames, overflowFlushed: false, overflowBytes: Data())
    }

    /// Any remaining bytes buffered but not yet part of a complete frame.
    public var remainingBytes: Data { buffer }

    // MARK: - Private

    /// Extract the next SSE frame from an already-decoded string, returning the frame
    /// and the next scan cursor. Called repeatedly from feed() without re-decoding.
    private func extractNextFrameFromString(
        _ str: String,
        from cursor: String.Index
    ) -> (Frame, String.Index)? {
        // Find the first blank-line terminator: \r\n\r\n preferred over \n\n.
        let terminators = ["\r\n\r\n", "\n\n"]
        var firstTermRange: Range<String.Index>?
        for term in terminators {
            if let r = str.range(of: term, range: cursor..<str.endIndex) {
                if firstTermRange == nil || r.lowerBound < firstTermRange!.lowerBound {
                    firstTermRange = r
                }
            }
        }

        guard let termRange = firstTermRange else { return nil }

        let frameStr = String(str[cursor..<termRange.lowerBound])
        let frameData = Data(str[cursor..<termRange.upperBound].utf8)
        let frame = parseFrame(frameStr, raw: frameData)

        return (frame, termRange.upperBound)
    }

    private func extractNextFrameRaw(from data: Data) -> (Frame, Data)? {
        guard data.count >= 2 else { return nil }
        let cr: UInt8 = 0x0D
        let nl: UInt8 = 0x0A
        for i in 0..<(data.count - 1) {
            if i + 3 < data.count,
               data[i] == cr, data[i + 1] == nl,
               data[i + 2] == cr, data[i + 3] == nl {
                let frameData = data.prefix(i + 4)
                let remaining = data.dropFirst(i + 4)
                let frame = parseFrameData(Data(frameData))
                return (frame, Data(remaining))
            }
            if data[i] == nl && data[i + 1] == nl {
                let frameData = data.prefix(i + 2)
                let remaining = data.dropFirst(i + 2)
                let frame = parseFrameData(Data(frameData))
                return (frame, Data(remaining))
            }
        }
        return nil
    }

    private func parseFrameData(_ raw: Data) -> Frame {
        // WO-291: strip terminators by byte count; String.dropLast() treats CRLF as graphemes.
        let bodyBytes: Data
        if raw.suffix(4) == Data([0x0D, 0x0A, 0x0D, 0x0A]) {
            bodyBytes = raw.dropLast(4)
        } else if raw.suffix(2) == Data([0x0A, 0x0A]) {
            bodyBytes = raw.dropLast(2)
        } else {
            bodyBytes = raw
        }
        guard let text = String(data: bodyBytes, encoding: .utf8) else {
            return Frame(raw: raw, eventType: nil, data: nil)
        }
        return parseFrame(text, raw: raw)
    }

    private func parseFrame(_ text: String, raw: Data) -> Frame {
        var eventType: String?
        var dataLines: [String] = []

        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .init(charactersIn: "\r"))
            if trimmed.hasPrefix("event:") {
                eventType = String(trimmed.dropFirst("event:".count)).trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("data:") {
                dataLines.append(String(trimmed.dropFirst("data:".count)).trimmingCharacters(in: .whitespaces))
            }
        }

        let dataPayload = dataLines.isEmpty ? nil : dataLines.joined(separator: "\n")
        return Frame(raw: raw, eventType: eventType, data: dataPayload)
    }
}

extension SSEFrameParser.Frame {
    /// Re-serialize this frame with a replacement data payload, preserving event type.
    /// Returns the original raw bytes if re-serialization would produce identical content.
    public func reserializedWith(data newData: String) -> Data {
        var lines: [String] = []
        if let et = eventType {
            lines.append("event: \(et)")
        }
        // Preserve multi-line data fields.
        for line in newData.components(separatedBy: "\n") {
            lines.append("data: \(line)")
        }
        lines.append("")
        lines.append("")
        return Data(lines.joined(separator: "\n").utf8)
    }
}
