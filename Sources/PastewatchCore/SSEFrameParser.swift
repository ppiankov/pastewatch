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

        // SSE frames are terminated by a blank line (\n\n or \r\n\r\n).
        while let (frame, remaining) = extractNextFrame(from: buffer) {
            frames.append(frame)
            buffer = remaining
        }

        return FeedResult(frames: frames, overflowFlushed: false, overflowBytes: Data())
    }

    /// Any remaining bytes buffered but not yet part of a complete frame.
    public var remainingBytes: Data { buffer }

    // MARK: - Private

    private func extractNextFrame(from data: Data) -> (Frame, Data)? {
        guard let bytes = String(data: data, encoding: .utf8) else {
            // Non-UTF-8: try to find the frame terminator byte-pattern and split raw.
            return extractNextFrameRaw(from: data)
        }

        // Find the first blank-line terminator: \n\n or \r\n\r\n.
        let terminators = ["\r\n\r\n", "\n\n"]
        var firstTermRange: Range<String.Index>?
        var termLen = 0
        for term in terminators {
            if let r = bytes.range(of: term) {
                if firstTermRange == nil || r.lowerBound < firstTermRange!.lowerBound {
                    firstTermRange = r
                    termLen = term.count
                }
            }
        }

        guard let termRange = firstTermRange else { return nil }

        let frameStr = String(bytes[..<termRange.lowerBound])
        let afterTerm = String(bytes[termRange.upperBound...])

        let frameData = Data((frameStr + String(bytes[termRange])).utf8)
        _ = termLen // suppress warning
        let frame = parseFrame(frameStr, raw: frameData)
        let remainingData = Data(afterTerm.utf8)

        return (frame, remainingData)
    }

    private func extractNextFrameRaw(from data: Data) -> (Frame, Data)? {
        // Byte search for \n\n
        let nl: UInt8 = 0x0A
        for i in 0..<(data.count - 1) {
            if data[i] == nl && data[i + 1] == nl {
                let frameData = data[0...i+1]
                let remaining = i + 2 < data.count ? data[(i + 2)...] : Data()
                let frame = Frame(raw: Data(frameData), eventType: nil, data: nil)
                return (frame, Data(remaining))
            }
        }
        return nil
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
