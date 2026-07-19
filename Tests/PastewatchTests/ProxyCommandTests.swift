@testable import PastewatchCLI
@testable import PastewatchCore
import XCTest
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class ProxyCommandTests: XCTestCase {
    // WO-473: the shared command gate rejects mixed valid/invalid rules before listen.
    func testProxyCustomRuleStartupGateRejectsWholeSet() {
        var config = PastewatchConfig.defaultConfig
        config.customRules = [
            CustomRuleConfig(name: "Valid", pattern: "SAFE-[0-9]+"),
            CustomRuleConfig(name: "Invalid", pattern: "[broken")
        ]

        XCTAssertThrowsError(try compileProxyCustomRules(config))
    }

    func testDirectProxyServerRejectsInvalidRuleBeforeListen() {
        let invalidPattern = "[" + "broken"
        var config = PastewatchConfig.defaultConfig
        config.customRules = [CustomRuleConfig(name: "Invalid", pattern: invalidPattern)]
        let server = ProxyServer(port: 0, config: config)

        XCTAssertThrowsError(try server.start()) { error in
            XCTAssertTrue(error.localizedDescription.contains("Invalid"))
            XCTAssertFalse(error.localizedDescription.contains(invalidPattern))
        }
    }

    // WO-275: quiet launch and normal peer disconnects are silent; unexpected
    // socket failures remain visible in explicit non-quiet proxy mode.
    func testSocketDeliveryFailureLoggingPolicy() {
        XCTAssertFalse(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EPIPE, quiet: false))
        XCTAssertFalse(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: ECONNRESET, quiet: false))
        XCTAssertFalse(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EIO, quiet: true))
        XCTAssertTrue(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EBADF, quiet: false))
        XCTAssertTrue(ProxyServer.shouldLogSocketDeliveryFailure(errorCode: EIO, quiet: false))
    }

    func testProxyShutdownExitCodeDistinguishesStartupInterrupt() {
        // WO-375: SIGINT before listen succeeds must not look like a clean shutdown.
        XCTAssertEqual(proxyShutdownExitCode(didStart: false), proxyInterruptedExitCode)
        XCTAssertNotEqual(proxyShutdownExitCode(didStart: false), 0)
    }

    func testProxyShutdownExitCodeKeepsCleanPostStartShutdownZero() {
        // WO-375: preserve the existing clean shutdown signal after listen succeeds.
        XCTAssertEqual(proxyShutdownExitCode(didStart: true), 0)
    }

    // WO-514: raw capture is available only through the explicit command-line option.
    func testDebugStreamDumpOptionIsExplicitAndWarns() throws {
        let command = try Proxy.parse(["--debug-stream-dump", "/tmp/pastewatch-stream.jsonl", "--quiet"])
        let ordinaryCommand = try Proxy.parse([])

        XCTAssertEqual(command.debugStreamDump, "/tmp/pastewatch-stream.jsonl")
        XCTAssertNil(ordinaryCommand.debugStreamDump)
        XCTAssertNotNil(streamDebugDumpWarning(path: command.debugStreamDump))
        XCTAssertNil(streamDebugDumpWarning(path: nil))
    }

    // WO-514: debug evidence files are owner-only and contain raw/output decision records.
    func testStreamDebugSinkCreatesOwnerOnlyJSONL() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-debug-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let sink = try StreamDebugSink(path: path)

        sink.record(inputs: [Data("raw-frame".utf8)], output: Data("mutated-frame".utf8), decision: "mutated")

        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let line = try XCTUnwrap(String(contentsOfFile: path).split(separator: "\n").first)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
        )
        XCTAssertEqual(object["decision"] as? String, "mutated")
        XCTAssertEqual(object["input_base64"] as? [String], [Data("raw-frame".utf8).base64EncodedString()])
    }

    // WO-514: each proxy invocation appends evidence instead of destroying an earlier capture.
    func testStreamDebugSinkAppendsToExistingCapture() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-debug-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let firstSink = try StreamDebugSink(path: path)
        firstSink.record(inputs: [Data("first".utf8)], output: Data(), decision: "unchanged")

        let secondSink = try StreamDebugSink(path: path)
        secondSink.record(inputs: [Data("second".utf8)], output: Data(), decision: "mutated")

        let lines = try String(contentsOfFile: path).split(separator: "\n")
        XCTAssertEqual(lines.count, 2)
    }

    // WO-514: a path swap cannot redirect raw secret evidence after startup.
    func testStreamDebugSinkDoesNotFollowReplacementSymlink() throws {
        let directory = NSTemporaryDirectory() + "pastewatch-stream-debug-\(UUID().uuidString)"
        let path = directory + "/capture.jsonl"
        let target = directory + "/attacker-target"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let sink = try StreamDebugSink(path: path)
        try Data("unchanged".utf8).write(to: URL(fileURLWithPath: target))
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)

        sink.record(inputs: [Data("raw-secret".utf8)], output: Data(), decision: "mutated")

        XCTAssertEqual(try String(contentsOfFile: target), "unchanged")
    }

    // WO-517: no-follow creation rejects existing symlinks even when their target is absent.
    func testStreamDebugSinkRejectsDanglingSymlink() throws {
        let directory = NSTemporaryDirectory() + "pastewatch-stream-debug-\(UUID().uuidString)"
        let path = directory + "/capture.jsonl"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: directory + "/missing")

        XCTAssertThrowsError(try StreamDebugSink(path: path))
    }

    // WO-514: an existing capture at the disk bound cannot grow through another record.
    func testStreamDebugSinkHonorsExistingFileSizeLimit() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-debug-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        XCTAssertTrue(FileManager.default.createFile(atPath: path, contents: nil))
        let handle = try XCTUnwrap(FileHandle(forWritingAtPath: path))
        handle.truncateFile(atOffset: UInt64(StreamDebugSink.maxBytes))
        handle.closeFile()
        let sink = try StreamDebugSink(path: path)

        sink.record(inputs: [Data("raw-secret".utf8)], output: Data(), decision: "mutated")

        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attributes[.size] as? NSNumber)?.intValue, StreamDebugSink.maxBytes)
    }

    // WO-514: unsupported relay modes fail before listen instead of writing an empty diagnostic.
    func testStreamDebugDumpRequiresPerSSEEventMode() throws {
        let path = NSTemporaryDirectory() + "pastewatch-stream-debug-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var config = PastewatchConfig.defaultConfig
        config.responseStreamingRedactionMode = .rawStream
        let server = ProxyServer(port: 0, config: config, streamDebugSink: try StreamDebugSink(path: path))

        XCTAssertThrowsError(try server.start()) { error in
            guard case ProxyError.streamDebugDumpRequiresPerSSEEvent = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }
}
