import XCTest
@testable import PastewatchCore

final class SSEFrameParserTests: XCTestCase {

    // MARK: - Basic frame extraction

    func testSingleCompleteFrame() {
        var parser = SSEFrameParser()
        let input = Data("event: message\ndata: hello\n\n".utf8)
        let result = parser.feed(input)
        XCTAssertEqual(result.frames.count, 1)
        XCTAssertEqual(result.frames[0].eventType, "message")
        XCTAssertEqual(result.frames[0].data, "hello")
        XCTAssertFalse(result.overflowFlushed)
        XCTAssertTrue(parser.remainingBytes.isEmpty)
    }

    func testMultipleFramesInOneChunk() {
        var parser = SSEFrameParser()
        let input = Data("data: one\n\ndata: two\n\ndata: three\n\n".utf8)
        let result = parser.feed(input)
        XCTAssertEqual(result.frames.count, 3)
        XCTAssertEqual(result.frames[0].data, "one")
        XCTAssertEqual(result.frames[1].data, "two")
        XCTAssertEqual(result.frames[2].data, "three")
    }

    func testManyFramesInOneChunkPreservesTrailingPartial() {
        var parser = SSEFrameParser()
        var stream = ""
        for i in 0..<1_000 {
            stream += "data: frame-\(i)\n\n"
        }
        stream += "data: partial"

        let result = parser.feed(Data(stream.utf8))

        XCTAssertEqual(result.frames.count, 1_000)
        XCTAssertEqual(result.frames.first?.data, "frame-0")
        XCTAssertEqual(result.frames.last?.data, "frame-999")
        XCTAssertEqual(parser.remainingBytes, Data("data: partial".utf8))
    }

    func testPartialFrameRetained() {
        var parser = SSEFrameParser()
        let chunk1 = Data("data: hel".utf8)
        let result1 = parser.feed(chunk1)
        XCTAssertEqual(result1.frames.count, 0)
        XCTAssertFalse(parser.remainingBytes.isEmpty)

        let chunk2 = Data("lo\n\n".utf8)
        let result2 = parser.feed(chunk2)
        XCTAssertEqual(result2.frames.count, 1)
        XCTAssertEqual(result2.frames[0].data, "hello")
        XCTAssertTrue(parser.remainingBytes.isEmpty)
    }

    func testFrameSplitAtTerminator() {
        var parser = SSEFrameParser()
        // Split right at the first \n of \n\n
        let chunk1 = Data("data: test\n".utf8)
        let result1 = parser.feed(chunk1)
        XCTAssertEqual(result1.frames.count, 0)

        let chunk2 = Data("\n".utf8)
        let result2 = parser.feed(chunk2)
        XCTAssertEqual(result2.frames.count, 1)
        XCTAssertEqual(result2.frames[0].data, "test")
    }

    func testFrameWithCRLFTerminator() {
        var parser = SSEFrameParser()
        let input = Data("data: hello\r\n\r\n".utf8)
        let result = parser.feed(input)
        XCTAssertEqual(result.frames.count, 1)
        XCTAssertEqual(result.frames[0].data, "hello")
    }

    func testCompleteFrameBeforeInvalidUTF8RemainderStillParsesData() {
        var parser = SSEFrameParser()
        let payload = #"{"delta":{"text":"hello"}}"#
        var input = Data("event: content_block_delta\ndata: \(payload)\n\n".utf8)
        let invalidRemainder = Data([0xFF, 0xFE])
        input.append(invalidRemainder)

        let result = parser.feed(input)

        XCTAssertEqual(result.frames.count, 1)
        XCTAssertEqual(result.frames[0].eventType, "content_block_delta")
        XCTAssertEqual(result.frames[0].data, payload)
        XCTAssertEqual(parser.remainingBytes, invalidRemainder)
    }

    func testInvalidUTF8FramePassesThroughUnparsed() {
        var parser = SSEFrameParser()
        let input = Data([0xFF, 0xFE, 0x0A, 0x0A])

        let result = parser.feed(input)

        XCTAssertEqual(result.frames.count, 1)
        XCTAssertNil(result.frames[0].eventType)
        XCTAssertNil(result.frames[0].data)
        XCTAssertEqual(result.frames[0].raw, input)
        XCTAssertTrue(parser.remainingBytes.isEmpty)
    }

    func testTerminalDoneFrame() {
        var parser = SSEFrameParser()
        let input = Data("data: [DONE]\n\n".utf8)
        let result = parser.feed(input)
        XCTAssertEqual(result.frames.count, 1)
        XCTAssertEqual(result.frames[0].data, "[DONE]")
    }

    func testControlPingFrame() {
        var parser = SSEFrameParser()
        let input = Data("event: ping\ndata: {}\n\n".utf8)
        let result = parser.feed(input)
        XCTAssertEqual(result.frames.count, 1)
        XCTAssertEqual(result.frames[0].eventType, "ping")
    }

    // MARK: - Overflow / fail-safe

    func testOversizedFrameFlushesRaw() {
        var parser = SSEFrameParser()
        // Create data larger than the 4MB max without a terminator.
        let bigPayload = Data(repeating: 0x41, count: SSEFrameParser.maxFrameBytes + 1)
        let result = parser.feed(bigPayload)
        XCTAssertTrue(result.overflowFlushed)
        XCTAssertEqual(result.overflowBytes.count, bigPayload.count)
        XCTAssertTrue(result.frames.isEmpty)
        // Buffer should be cleared after overflow.
        XCTAssertTrue(parser.remainingBytes.isEmpty)
    }

    // MARK: - Boundary / fuzz: same stream, different chunkings

    func testIdenticalOutputForArbitraryChunkings() {
        let stream = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"hello\"}}\n\nevent: message_stop\ndata: [DONE]\n\n"
        let streamData = Data(stream.utf8)

        // Collect all frame raw bytes from a full-chunk parse.
        var refParser = SSEFrameParser()
        let refResult = refParser.feed(streamData)
        let refOutput = refResult.frames.map { $0.raw }

        // Try various chunk sizes and assert the assembled frames match.
        for chunkSize in [1, 2, 3, 7, 13, 27, streamData.count] {
            var parser = SSEFrameParser()
            var allFrames: [Data] = []
            var offset = 0
            while offset < streamData.count {
                let end = min(offset + chunkSize, streamData.count)
                let chunk = streamData[offset..<end]
                let result = parser.feed(Data(chunk))
                allFrames.append(contentsOf: result.frames.map { $0.raw })
                offset = end
            }
            XCTAssertEqual(allFrames.count, refOutput.count,
                           "Chunk size \(chunkSize): frame count mismatch")
            for (i, frame) in allFrames.enumerated() {
                XCTAssertEqual(frame, refOutput[i],
                               "Chunk size \(chunkSize): frame \(i) content mismatch")
            }
        }
    }

    // MARK: - Reserialization

    func testReserializedWithPreservesEventType() {
        var parser = SSEFrameParser()
        let input = Data("event: content_block_delta\ndata: original\n\n".utf8)
        let frames = parser.feed(input).frames
        XCTAssertEqual(frames.count, 1)

        let reserialized = frames[0].reserializedWith(data: "redacted")
        let reserializedStr = String(data: reserialized, encoding: .utf8) ?? ""
        XCTAssertTrue(reserializedStr.contains("event: content_block_delta"))
        XCTAssertTrue(reserializedStr.contains("data: redacted"))
        XCTAssertFalse(reserializedStr.contains("original"))
    }
}
