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

        // WO-168: decode the buffer once per feed() call, then extract all frames in the
        // string domain. The old extractNextFrame() decoded the whole buffer on every frame
        // iteration — O(N×M) for N frames in one chunk. Non-UTF-8 data falls through to the
        // raw byte-search path as before.
        if var remaining = String(data: buffer, encoding: .utf8) {
            while let (frame, rest) = extractNextFrameFromString(remaining) {
                frames.append(frame)
                remaining = rest
            }
            buffer = Data(remaining.utf8)
        } else {
            // Non-UTF-8: use the raw byte-search path.
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
    /// and the unconsumed remainder. Called repeatedly from feed() without re-decoding.
    private func extractNextFrameFromString(_ str: String) -> (Frame, String)? {
        // Find the first blank-line terminator: \r\n\r\n preferred over \n\n.
        let terminators = ["\r\n\r\n", "\n\n"]
        var firstTermRange: Range<String.Index>?
        for term in terminators {
            if let r = str.range(of: term) {
                if firstTermRange == nil || r.lowerBound < firstTermRange!.lowerBound {
                    firstTermRange = r
                }
            }
        }

        guard let termRange = firstTermRange else { return nil }

        let frameStr = String(str[..<termRange.lowerBound])
        let terminator = String(str[termRange])
        let afterTerm = String(str[termRange.upperBound...])

        let frameData = Data((frameStr + terminator).utf8)
        let frame = parseFrame(frameStr, raw: frameData)

        return (frame, afterTerm)
    }

    private func extractNextFrameRaw(from data: Data) -> (Frame, Data)? {
        guard data.count >= 2 else { return nil }
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
