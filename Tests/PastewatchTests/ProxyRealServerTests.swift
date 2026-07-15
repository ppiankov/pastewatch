import XCTest
@testable import PastewatchCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// WO-319/WO-322: real TCP proxy harness tests for admission and forwarding behavior.
final class ProxyRealServerTests: XCTestCase {

    func testRealProxyRoundTripsBufferedResponse() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: TCPTestSocket.validAnthropicMessagesBody),
            timeoutSeconds: 10
        )

        let admission = proxy.connectionAdmissionStats
        let diagnostic = TCPTestSocket.describeResponse(response) +
            " proxy_processed=\(proxy.stats.requestsProcessed)" +
            " proxy_rejected=\(admission.rejected)" +
            " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertTrue(response.contains(#"{"ok":true}"#), diagnostic)
    }

    // WO-420: a supported Anthropic body passes the shape guard and is redacted before upstream.
    func testAnthropicBodyRedactedThroughShapeGuardBeforeUpstream() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let credential = "password=s3cr3t-hunter2"
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"\(credential)"}]}]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
            timeoutSeconds: 10
        )

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 1, diagnostic)
        XCTAssertFalse(forwarded.contains(credential), "upstream request leaked raw credential")
        XCTAssertTrue(forwarded.contains("<CREDENTIAL_1>"), "upstream request missing redaction placeholder")
    }

    // WO-462/WO-478/WO-479/WO-481/WO-482/WO-483/WO-485: the real proxy
    // must contain complete intrinsic tokens and payload-bearing credentials.
    func testIntrinsicProviderTokensAndPayloadsDoNotReachUpstream() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let slackStem = String(decoding: [120, 111, 120], as: UTF8.self)
        let providerSecrets = [
            "hvs." + String(repeating: "A1", count: 12),
            slackStem + "b-1234567890-" + String(repeating: "Ab", count: 12),
            "AIza" + String(repeating: "K", count: 35),
            "dckr_pat_" + String(repeating: "Lm", count: 12),
            "github_pat_" + String(repeating: "Pq", count: 20),
            providerPEMFixture(label: "OPENSSH PRIVATE KEY", payload: String(repeating: "QUJD", count: 12))
        ]
        let gcpKeyID = String(repeating: "a1", count: 20)
        let gcpKey = providerPEMFixture(label: "PRIVATE KEY", payload: String(repeating: "R0NQ", count: 12))
        let gcpData = try JSONSerialization.data(withJSONObject: [
            "type": "service_account",
            "private_key_id": gcpKeyID,
            "private_key": gcpKey
        ], options: [.sortedKeys])
        let gcpJSON = try XCTUnwrap(String(data: gcpData, encoding: .utf8))
        let requestObject: [String: Any] = [
            "model": "claude-3",
            "messages": [[
                "role": "user",
                "content": [
                    ["type": "tool_result", "tool_use_id": "toolu_1", "content": providerSecrets.joined(separator: "\n")],
                    ["type": "tool_result", "tool_use_id": "toolu_2", "content": gcpJSON]
                ]
            ]]
        ]
        let bodyData = try JSONSerialization.data(withJSONObject: requestObject, options: [.sortedKeys])
        let body = try XCTUnwrap(String(data: bodyData, encoding: .utf8))
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
            timeoutSeconds: 10
        )

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), TCPTestSocket.describeResponse(response))
        for secret in providerSecrets + [gcpKeyID, gcpKey] {
            XCTAssertFalse(forwarded.contains(secret), "upstream request leaked a raw intrinsic secret")
        }
        XCTAssertGreaterThanOrEqual(proxy.stats.requestsRedacted, 1)
    }

    // WO-437: top-level system text is part of the Anthropic request shape and must be scanned.
    func testAnthropicSystemFieldCredentialRedactedThroughShapeGuardBeforeUpstream() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let credential = "password=system-hunter2"
        let body = """
        {"model":"claude-3","system":"\(credential)","messages":[{"role":"user","content":"hello"}]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
            timeoutSeconds: 10
        )

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 1, diagnostic)
        XCTAssertFalse(forwarded.contains(credential), "upstream system field leaked raw credential")
        XCTAssertTrue(forwarded.contains("<CREDENTIAL_1>"), "upstream system field missing redaction placeholder")
    }

    // WO-447: array-form system text is scanned without dropping block metadata.
    func testAnthropicSystemTextBlocksRedactedAndMetadataPreserved() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let credential = "password=system-block-hunter2"
        let body = """
        {"model":"claude-3","system":[{"type":"text","text":"\(credential)","cache_control":{"type":"ephemeral"}},{"type":"image","source":"unchanged"}],"messages":[{"role":"user","content":"hello"}]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
            timeoutSeconds: 10
        )

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), TCPTestSocket.describeResponse(response))
        XCTAssertFalse(forwarded.contains(credential), "upstream system block leaked raw credential")
        XCTAssertTrue(forwarded.contains("<CREDENTIAL_1>"), "upstream system block missing placeholder")
        XCTAssertTrue(forwarded.contains(#""cache_control":{"type":"ephemeral"}"#), forwarded)
        XCTAssertTrue(forwarded.contains(#""source":"unchanged""#), forwarded)
    }

    // WO-432: Message Batch params pass the shape guard and use the same request redactor.
    func testAnthropicMessageBatchRedactedThroughShapeGuardBeforeUpstream() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(
                status: 202,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"id":"batch_1"}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let credential = "password=batch-hunter2"
        let body = """
        {"requests":[{"custom_id":"r1","params":{"model":"claude-3","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"\(credential)"}]}]}}]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages/batches", body: body),
            timeoutSeconds: 10
        )

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 202 Accepted"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 1, diagnostic)
        XCTAssertTrue(forwarded.contains("POST /v1/messages/batches HTTP/1.1"), forwarded)
        XCTAssertFalse(forwarded.contains(credential), "upstream batch request leaked raw credential")
        XCTAssertTrue(forwarded.contains("<CREDENTIAL_1>"), "upstream batch request missing redaction placeholder")
    }

    // WO-444/WO-447: every batch params.system representation uses the same scanner as
    // a single Messages request, while the existing tool_result walk remains active.
    func testAnthropicMessageBatchRedactsSystemFormsAndToolResults() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(status: 202, headers: [:], body: Data(#"{"id":"batch_1"}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let stringCredential = "password=batch-system-string-hunter2"
        let blockCredential = "password=batch-system-block-hunter2"
        let toolCredential = "password=batch-tool-hunter2"
        let body = """
        {"requests":[
          {"custom_id":"string","params":{"model":"claude-3","system":"\(stringCredential)","messages":[{"role":"user","content":"hello"}]}},
          {"custom_id":"blocks","params":{"model":"claude-3","system":[{"type":"text","text":"\(blockCredential)","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hello"}]}},
          {"custom_id":"tool","params":{"model":"claude-3","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"\(toolCredential)"}]}]}}
        ]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages/batches", body: body),
            timeoutSeconds: 10
        )

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        XCTAssertTrue(response.contains("HTTP/1.1 202 Accepted"), TCPTestSocket.describeResponse(response))
        for credential in [stringCredential, blockCredential, toolCredential] {
            XCTAssertFalse(forwarded.contains(credential), "upstream batch leaked \(credential)")
        }
        XCTAssertTrue(forwarded.contains("<CREDENTIAL_"), "upstream batch missing placeholders")
        XCTAssertTrue(forwarded.contains(#""cache_control":{"type":"ephemeral"}"#), forwarded)
    }

    // WO-433: an empty POST body has no body shape to scan and must still reach upstream.
    func testEmptyPostBodyForwardedThroughShapeGuard() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: ""),
            timeoutSeconds: 10
        )

        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertFalse(response.contains("HTTP/1.1 415"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 1, diagnostic)
    }

    // WO-424: gateway-prefixed Anthropic paths must forward through the real proxy.
    func testGatewayPrefixedAnthropicBodyRedactedAndForwarded() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let credential = "password=gateway-hunter2"
        let body = """
        {"model":"claude-3","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"\(credential)"}]}]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/llm-gateway/v1/messages", body: body),
            timeoutSeconds: 10
        )

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertFalse(response.contains("HTTP/1.1 415"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 1, diagnostic)
        XCTAssertTrue(forwarded.contains("POST /v1/llm-gateway/v1/messages HTTP/1.1"), forwarded)
        XCTAssertFalse(forwarded.contains(credential), "upstream request leaked raw credential")
        XCTAssertTrue(forwarded.contains("<CREDENTIAL_1>"), "upstream request missing redaction placeholder")
    }

    // WO-421: streaming Anthropic requests also pass the shape guard and reach upstream.
    func testStreamingAnthropicBodyAllowedThroughShapeGuard() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "text/event-stream"],
                body: Data("data: [DONE]\n\n".utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let body = """
        {"model":"claude-3","stream":true,"messages":[{"role":"user","content":"hello"}]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertFalse(response.contains("HTTP/1.1 415"), diagnostic)
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 1, diagnostic)
    }

    // WO-408/WO-411: an OpenAI-shaped body is refused with 415 and never reaches upstream.
    func testUnsupportedBodyShapeRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let openAIBody = #"{"model":"gpt-4","messages":[{"role":"user","content":"x"}]}"#
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/chat/completions", body: openAIBody),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertTrue(response.contains(#""error": "Unsupported upstream body shape""#), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "foreign body must not reach upstream; \(diagnostic)")
    }

    // WO-422: parseable JSON arrays on unsupported paths fail closed.
    func testTopLevelJSONArrayRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/chat/completions", body: #"[{"role":"user","content":"x"}]"#),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "JSON array body must not reach upstream; \(diagnostic)")
    }

    // WO-422: non-UTF-8 bodies on foreign paths fail closed instead of bypassing scanning.
    func testNonUTF8ForeignPathRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let request = TCPTestSocket.postRequestData(
            path: "/v1/chat/completions",
            body: Data([0xff, 0xfe, 0xfd])
        )
        let response = try TCPTestSocket.roundTrip(port: proxyPort, requestData: request, timeoutSeconds: 10)
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "non-UTF-8 foreign body must not reach upstream; \(diagnostic)")
    }

    // WO-425: malformed supported-path bodies fail closed instead of forwarding unscanned bytes.
    func testNonJSONMessagesPathRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: "not json password=messages-hunter2"),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "malformed messages body must not reach upstream; \(diagnostic)")
    }

    // WO-425: a JSON object without the Messages scan shape is not safe passthrough.
    func testMessagesPathWithoutMessagesArrayRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let body = #"{"model":"claude-3","input":"password=messages-hunter2"}"#
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "non-message JSON body must not reach upstream; \(diagnostic)")
    }

    // WO-412: unsupported JSON POST bodies without messages arrays are also refused.
    func testUnsupportedJSONPostWithoutMessagesRefusedBeforeUpstream() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertTrue(response.contains(#""error": "Unsupported upstream body shape""#), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "unsupported body must not reach upstream; \(diagnostic)")
    }

    // WO-413: quiet mode suppresses stderr, not durable audit evidence.
    func testUnsupportedBodyShapeRefusalWritesAuditLogWhenQuiet() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-refused-shape-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        var proxyStopped = false
        defer {
            if !proxyStopped {
                runningProxy.stop()
            }
        }

        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
            timeoutSeconds: 10
        )
        runningProxy.stop()
        proxyStopped = true

        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, "unsupported body must not reach upstream; \(diagnostic)")

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertTrue(audit.contains("PROXY REFUSED unsupported upstream body shape"), audit)
        XCTAssertTrue(audit.contains("/v1/responses"), audit)
        XCTAssertTrue(audit.contains("unsupported JSON POST body"), audit)
    }

    // WO-424: non-quiet refusals write the same audit signal to stderr.
    func testUnsupportedBodyShapeRefusalWritesStderrWhenNotQuiet() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            quietLog: false
        )
        let runningProxy = RunningProxy(server: proxy)
        let responseBox = LockedValue("")
        let stderr = try captureStandardError {
            try runningProxy.start()
            defer { runningProxy.stop() }
            let response = try TCPTestSocket.roundTrip(
                port: proxyPort,
                request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
                timeoutSeconds: 10
            )
            responseBox.set(response)
        }

        let response = responseBox.value
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 0, diagnostic)
        XCTAssertTrue(stderr.contains("PROXY REFUSED unsupported upstream body shape"), stderr)
        XCTAssertTrue(stderr.contains("/v1/responses"), stderr)
        XCTAssertTrue(stderr.contains("unsupported JSON POST body"), stderr)
    }

    func testUnsupportedBodyBearingMethodsAreRefusedBeforeUpstream() throws {
        // WO-422: no method may carry an unscanned body through the proxy.
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let body = #"{"model":"claude-3","messages":[{"role":"user","content":"password=method-hunter2"}]}"#
        for method in ["post", "PUT", "PATCH", "GET"] {
            let response = try TCPTestSocket.roundTrip(
                port: proxyPort,
                request: TCPTestSocket.request(method: method, path: "/v1/messages", body: body),
                timeoutSeconds: 10
            )
            XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), "\(method): \(response)")
        }
        XCTAssertEqual(upstream.requestCount, 0)
        XCTAssertEqual(proxy.stats.refusedRequests, 4)
    }

    // WO-440/WO-442: repeated unsupported-shape refusals are counted but audit-deduped.
    func testRepeatedUnsupportedBodyShapeRefusalsAreDedupedAndCounted() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-refused-dedup-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        var proxyStopped = false
        defer {
            if !proxyStopped {
                runningProxy.stop()
            }
        }

        for path in ["/v1/responses", "/v1/responses", "/v1/chat/completions"] {
            _ = try TCPTestSocket.roundTrip(
                port: proxyPort,
                request: TCPTestSocket.postRequest(path: path, body: #"{"input":"hello"}"#),
                timeoutSeconds: 10
            )
        }
        runningProxy.stop()
        proxyStopped = true

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertEqual(proxy.stats.refusedRequests, 3)
        XCTAssertEqual(proxy.stats.requestsProcessed, 0)
        XCTAssertEqual(proxy.stats.requestsRedacted, 0)
        XCTAssertEqual(upstream.requestCount, 0)
        XCTAssertEqual(audit.components(separatedBy: "PROXY REFUSED").count - 1, 2, audit)
        XCTAssertTrue(audit.contains("/v1/responses"), audit)
        XCTAssertTrue(audit.contains("/v1/chat/completions"), audit)
    }

    // WO-440: a real redaction event between refusals breaks only the refusal dedup chain.
    func testRefusalDedupResetsAfterRedactionAudit() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-refused-reset-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        var proxyStopped = false
        defer {
            if !proxyStopped {
                runningProxy.stop()
            }
        }

        let redactedBody = """
        {"model":"claude-3","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"password=reset-hunter2"}]}]}
        """
        _ = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
            timeoutSeconds: 10
        )
        _ = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: redactedBody),
            timeoutSeconds: 10
        )
        _ = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
            timeoutSeconds: 10
        )
        runningProxy.stop()
        proxyStopped = true

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertEqual(audit.components(separatedBy: "PROXY REFUSED").count - 1, 2, audit)
        XCTAssertEqual(audit.components(separatedBy: "PROXY REDACTED").count - 1, 1, audit)
        XCTAssertEqual(proxy.stats.refusedRequests, 2)
        XCTAssertEqual(proxy.stats.requestsProcessed, 1)
    }

    // WO-448: a refusal must also break the preceding redaction dedup chain.
    func testRedactionDedupResetsAfterRefusalAudit() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-redaction-reset-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let body = #"{"model":"claude-3","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"password=reset-hunter2"}]}]}"#
        for path in ["/v1/messages", "/v1/responses", "/v1/messages"] {
            let requestBody = path == "/v1/messages" ? body : #"{"input":"hello"}"#
            _ = try TCPTestSocket.roundTrip(
                port: proxyPort,
                request: TCPTestSocket.postRequest(path: path, body: requestBody),
                timeoutSeconds: 10
            )
        }
        proxy.drainAuditLogForTesting()

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertEqual(audit.components(separatedBy: "PROXY REDACTED").count - 1, 2, audit)
        XCTAssertEqual(audit.components(separatedBy: "PROXY REFUSED").count - 1, 1, audit)
        XCTAssertEqual(proxy.stats.requestsProcessed, 2)
        XCTAssertEqual(proxy.stats.refusedRequests, 1)
    }

    // WO-448: a refusal must break the preceding advisory dedup chain as well.
    func testAdvisoryDedupResetsAfterRefusalAudit() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data())
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-advisory-reset-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        proxy.recordBodyAdvisoryStats(path: "/v1/messages", count: 1, types: ["Email"])
        _ = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/responses", body: #"{"input":"hello"}"#),
            timeoutSeconds: 10
        )
        proxy.recordBodyAdvisoryStats(path: "/v1/messages", count: 1, types: ["Email"])
        proxy.drainAuditLogForTesting()

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertEqual(audit.components(separatedBy: "PROXY ADVISORY").count - 1, 2, audit)
        XCTAssertEqual(audit.components(separatedBy: "PROXY REFUSED").count - 1, 1, audit)
        XCTAssertEqual(proxy.stats.advisoryMatches, 2)
        XCTAssertEqual(proxy.stats.refusedRequests, 1)
    }

    // WO-486: a refused request must not copy query material into an audit record.
    func testRefusalAuditOmitsQueryMaterial() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data())
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-audit-query-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let queryValue = "synthetic-query-value"
        _ = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(
                path: "/v1/responses?secret=\(queryValue)",
                body: #"{"input":"hello"}"#
            ),
            timeoutSeconds: 10
        )
        proxy.drainAuditLogForTesting()

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertTrue(audit.contains("PROXY REFUSED unsupported upstream body shape in /v1/responses"), audit)
        XCTAssertFalse(audit.contains("?secret="), audit)
        XCTAssertFalse(audit.contains(queryValue), audit)
        XCTAssertEqual(upstream.requestCount, 0)
    }

    // WO-430: nonstandard model names are forwarded on a valid Messages wire shape
    // and surfaced only through aggregate telemetry plus an off-band audit advisory.
    func testNonstandardModelIdentityIsForwardedAndAdvisoryOnly() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-model-advisory-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        for model in ["claude-3", "qwen-max"] {
            let body = """
            {"model":"\(model)","messages":[{"role":"user","content":"hello"}]}
            """
            let response = try TCPTestSocket.roundTrip(
                port: proxyPort,
                request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
                timeoutSeconds: 10
            )
            XCTAssertFalse(response.contains("HTTP/1.1 415"), model)
        }
        proxy.drainAuditLogForTesting()

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertEqual(upstream.requestCount, 2)
        XCTAssertEqual(proxy.stats.requestsProcessed, 2)
        XCTAssertEqual(proxy.stats.modelIdentityAdvisories, 1)
        XCTAssertEqual(proxy.stats.modelIdentityAdvisoryRate, 0.5, accuracy: 0.000_001)
        XCTAssertEqual(audit.components(separatedBy: "nonstandard model identity").count - 1, 1, audit)
        XCTAssertTrue(audit.contains("rate=1/2"), audit)
        XCTAssertFalse(audit.contains("qwen-max"), audit)
    }

    // WO-445: adjacent duplicates are quiet, while a distinct model identity emits a
    // new opaque advisory without changing aggregate request telemetry.
    func testModelIdentityAdvisoryDeduplicatesByPathAndModel() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-model-dedup-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let requests = [
            (model: "qwen-max", path: "/v1/messages"),
            (model: "qwen-max", path: "/v1/messages"),
            (model: "deepseek-chat", path: "/v1/messages"),
            (model: "qwen-max", path: "/gateway/v1/messages"),
        ]
        for request in requests {
            let body = """
            {"model":"\(request.model)","messages":[{"role":"user","content":"hello"}]}
            """
            _ = try TCPTestSocket.roundTrip(
                port: proxyPort,
                request: TCPTestSocket.postRequest(path: request.path, body: body),
                timeoutSeconds: 10
            )
        }
        proxy.drainAuditLogForTesting()

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertEqual(upstream.requestCount, 4)
        XCTAssertEqual(proxy.stats.requestsProcessed, 4)
        XCTAssertEqual(proxy.stats.modelIdentityAdvisories, 4)
        XCTAssertEqual(audit.components(separatedBy: "nonstandard model identity").count - 1, 3, audit)
        XCTAssertFalse(audit.contains("qwen-max"), audit)
        XCTAssertFalse(audit.contains("deepseek-chat"), audit)
    }

    // WO-443: refusal and model-advisory lines break each other's dedup chain, while
    // adjacent duplicates within either category remain independently suppressed.
    func testRefusalAndModelAdvisoryDedupResetSymmetrically() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-cross-dedup-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let advisoryBody = #"{"model":"qwen-max","messages":[{"role":"user","content":"hello"}]}"#
        let refusedBody = #"{"model":"gpt-4","messages":[{"role":"assistant","content":"hi","function_call":{"name":"f"}}]}"#
        for body in [advisoryBody, refusedBody, advisoryBody, refusedBody] {
            _ = try TCPTestSocket.roundTrip(
                port: proxyPort,
                request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
                timeoutSeconds: 10
            )
        }
        proxy.drainAuditLogForTesting()

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertEqual(upstream.requestCount, 2)
        XCTAssertEqual(proxy.stats.requestsProcessed, 2)
        XCTAssertEqual(proxy.stats.modelIdentityAdvisories, 2)
        XCTAssertEqual(proxy.stats.refusedRequests, 2)
        XCTAssertEqual(audit.components(separatedBy: "nonstandard model identity").count - 1, 2, audit)
        XCTAssertEqual(audit.components(separatedBy: "PROXY REFUSED").count - 1, 2, audit)
    }

    // WO-408: an Anthropic-shaped count-tokens body is forwarded, not falsely refused.
    func testAnthropicCountTokensNotRefused() throws {
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"input_tokens":3}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let body = #"{"model":"claude-3","messages":[{"role":"user","content":"count me"}]}"#
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages/count_tokens", body: body),
            timeoutSeconds: 10
        )
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertFalse(response.contains("HTTP/1.1 415"), "count_tokens wrongly refused; \(diagnostic)")
        XCTAssertEqual(upstream.requestCount, 1, "count_tokens must be forwarded; \(diagnostic)")
    }

    // WO-437: valid count_tokens bodies scan top-level system text.
    func testCountTokensSystemFieldCredentialRedacted() throws {
        let requestLock = NSLock()
        var upstreamRequest = ""
        let upstream = try StubHTTPServer { request in
            requestLock.lock()
            upstreamRequest = String(data: request, encoding: .utf8) ?? ""
            requestLock.unlock()
            return StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"input_tokens":3}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-count-tokens-system-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        var proxyStopped = false
        defer {
            if !proxyStopped {
                runningProxy.stop()
            }
        }

        let credential = "password=count-tokens-hunter2"
        let body = #"{"model":"claude-3","system":"\#(credential)","messages":[{"role":"user","content":"count"}]}"#
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages/count_tokens", body: body),
            timeoutSeconds: 10
        )
        runningProxy.stop()
        proxyStopped = true

        requestLock.lock()
        let forwarded = upstreamRequest
        requestLock.unlock()
        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        let diagnostic = TCPTestSocket.describeResponse(response) + " upstream_requests=\(upstream.requestCount)"
        XCTAssertTrue(response.contains("HTTP/1.1 200 OK"), diagnostic)
        XCTAssertEqual(upstream.requestCount, 1, diagnostic)
        XCTAssertFalse(forwarded.contains(credential), "upstream count_tokens request leaked raw credential")
        XCTAssertTrue(forwarded.contains("<CREDENTIAL_1>"), "upstream request missing redaction placeholder")
        XCTAssertTrue(audit.contains("PROXY REDACTED 1 secret(s) in /v1/messages/count_tokens"), audit)
        XCTAssertTrue(audit.contains("Credential x1"), audit)
    }

    func testCountTokensWithoutMessagesIsRefusedBeforeUpstream() throws {
        // WO-437: arbitrary JSON is not a valid Count Tokens shape and cannot bypass scanning.
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"input_tokens":3}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort, upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let body = #"{"input":"password=count-tokens-hunter2"}"#
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/gateway/v1/messages/count_tokens/", body: body),
            timeoutSeconds: 10
        )

        XCTAssertTrue(response.contains("HTTP/1.1 415 Unsupported Media Type"), response)
        XCTAssertEqual(upstream.requestCount, 0)
        XCTAssertEqual(proxy.stats.refusedRequests, 1)
    }

    func testSerializationFailureBlocksForwardingAndPreservesAdvisoryEvidence() throws {
        // WO-452/WO-458: serializer failure is observable and cannot discard scan evidence.
        let upstream = try StubHTTPServer { _ in
            StubHTTPResponse(status: 200, headers: [:], body: Data(#"{"ok":true}"#.utf8))
        }
        try upstream.start()
        defer { upstream.stop() }

        let auditPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("pastewatch-redaction-failure-\(UUID().uuidString).log")
        defer { try? FileManager.default.removeItem(at: auditPath) }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!,
            severity: .low,
            auditLogPath: auditPath.path,
            quietLog: true
        )
        proxy.requestBodySerializer = { _ in throw CocoaError(.fileWriteUnknown) }
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let rawCredential = "password=serialization-hunter2"
        let rawEmail = "operator@example.net"
        let body = """
        {"model":"claude-3","system":"\(rawCredential) \(rawEmail)","messages":[{"role":"user","content":"hello"}]}
        """
        let response = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: body),
            timeoutSeconds: 10
        )
        proxy.drainAuditLogForTesting()

        let audit = try String(contentsOf: auditPath, encoding: .utf8)
        XCTAssertTrue(response.contains("HTTP/1.1 500 Internal Server Error"), response)
        XCTAssertEqual(upstream.requestCount, 0)
        XCTAssertEqual(proxy.stats.redactionFailures, 1)
        XCTAssertEqual(proxy.stats.requestsProcessed, 0)
        XCTAssertEqual(proxy.stats.requestsRedacted, 0)
        XCTAssertEqual(proxy.stats.secretsRedacted, 0)
        XCTAssertEqual(proxy.stats.advisoryMatches, 1)
        XCTAssertTrue(audit.contains("PROXY REDACTION FAILED 1 secret(s) in /v1/messages"), audit)
        XCTAssertTrue(audit.contains("PROXY ADVISORY 1 possible secret match(es) in /v1/messages"), audit)
        XCTAssertFalse(audit.contains("PROXY REDACTED"), audit)
        XCTAssertFalse(audit.contains(rawCredential), audit)
        XCTAssertFalse(audit.contains(rawEmail), audit)
    }

    func testAdmissionCapRejectsFifthConcurrentConnection() throws {
        let upstreamEntered = DispatchSemaphore(value: 0)
        let upstreamRelease = DispatchSemaphore(value: 0)
        let upstream = try StubHTTPServer { _ in
            upstreamEntered.signal()
            _ = upstreamRelease.wait(timeout: .now() + 5)
            return StubHTTPResponse(
                status: 200,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"held":true}"#.utf8)
            )
        }
        try upstream.start()
        defer { upstream.stop() }

        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(
            port: proxyPort,
            upstream: URL(string: "http://127.0.0.1:\(upstream.port)")!
        )
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let group = DispatchGroup()
        let responseLock = NSLock()
        var heldResponses = Array(repeating: "", count: proxyMaxActiveConnections)
        for index in 0..<proxyMaxActiveConnections {
            group.enter()
            runDetached {
                let response = (try? TCPTestSocket.roundTrip(
                    port: proxyPort,
                    request: TCPTestSocket.postRequest(path: "/v1/messages", body: TCPTestSocket.validAnthropicMessagesBody),
                    timeoutSeconds: 5
                )) ?? ""
                responseLock.lock()
                heldResponses[index] = response
                responseLock.unlock()
                group.leave()
            }
        }

        for _ in 0..<proxyMaxActiveConnections {
            XCTAssertEqual(upstreamEntered.wait(timeout: .now() + 3), .success)
        }
        eventually(timeout: 3) {
            proxy.connectionAdmissionStats.active == proxyMaxActiveConnections
        }

        let rejected = try TCPTestSocket.roundTrip(
            port: proxyPort,
            request: TCPTestSocket.postRequest(path: "/v1/messages", body: TCPTestSocket.validAnthropicMessagesBody),
            timeoutSeconds: 3
        )
        XCTAssertTrue(rejected.contains("HTTP/1.1 503 Service Unavailable"))
        XCTAssertTrue(rejected.contains(#""error": "Proxy admission timeout""#))
        XCTAssertGreaterThanOrEqual(proxy.connectionAdmissionStats.rejected, 1)

        for _ in 0..<proxyMaxActiveConnections {
            upstreamRelease.signal()
        }
        XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(heldResponses.allSatisfy { $0.contains("HTTP/1.1 200 OK") })
    }

    func testAdmitConnectionIncrementsActiveBeforeReturning() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        for expectedActive in 1...proxyMaxActiveConnections {
            XCTAssertTrue(proxy.admitConnectionForTesting())
            XCTAssertEqual(proxy.connectionAdmissionStats.active, expectedActive)
        }

        for expectedActive in stride(from: proxyMaxActiveConnections - 1, through: 0, by: -1) {
            proxy.finishAdmittedConnectionForTesting()
            XCTAssertEqual(proxy.connectionAdmissionStats.active, expectedActive)
        }
    }

    func testAdmitConnectionAfterStopSendsHTTP503ToAcceptedSocket() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        let sockets = try TCPTestSocket.socketPair()
        defer { close(sockets.client) }
        defer { close(sockets.server) }

        proxy.stopAdmissionForTesting()

        XCTAssertFalse(proxy.admitConnectionForTesting(sockets.server))
        let response = try TCPTestSocket.readHTTPMessage(from: sockets.client, timeoutSeconds: 2)
        let text = String(data: response, encoding: .utf8) ?? ""

        XCTAssertTrue(text.contains("HTTP/1.1 503 Service Unavailable"), TCPTestSocket.describeResponse(text))
        XCTAssertTrue(text.contains(#""error": "Service Unavailable""#), TCPTestSocket.describeResponse(text))
    }

    func testQueuedAdmissionAfterStopSendsHTTP503WhenSlotOpens() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        var heldSlots = 0
        for _ in 0..<proxyMaxActiveConnections {
            XCTAssertTrue(proxy.admitConnectionForTesting())
            heldSlots += 1
        }
        defer {
            for _ in 0..<heldSlots {
                proxy.finishAdmittedConnectionForTesting()
            }
        }

        let sockets = try TCPTestSocket.socketPair()
        defer { close(sockets.client) }
        let finished = DispatchSemaphore(value: 0)
        let admittedLock = NSLock()
        var admitted: Bool?
        runDetached {
            let result = proxy.admitConnectionForTesting(sockets.server)
            admittedLock.lock()
            admitted = result
            admittedLock.unlock()
            close(sockets.server)
            finished.signal()
        }
        eventually(timeout: 1) {
            proxy.connectionAdmissionStats.queued == 1
        }

        proxy.stopAdmissionForTesting()
        proxy.finishAdmittedConnectionForTesting()
        heldSlots -= 1

        XCTAssertEqual(finished.wait(timeout: .now() + 2), .success)
        admittedLock.lock()
        let admittedResult = admitted
        admittedLock.unlock()
        XCTAssertEqual(admittedResult, false)
        let response = try TCPTestSocket.readHTTPMessage(from: sockets.client, timeoutSeconds: 2)
        let text = String(data: response, encoding: .utf8) ?? ""

        XCTAssertTrue(text.contains("HTTP/1.1 503 Service Unavailable"), TCPTestSocket.describeResponse(text))
        XCTAssertTrue(text.contains(#""error": "Service Unavailable""#), TCPTestSocket.describeResponse(text))
    }

    func testQueuedAdmissionAfterStopSendsHTTP503WhenQueueTimeoutExpires() throws {
        let proxyPort = try TCPTestSocket.reserveLoopbackPort()
        let proxy = ProxyServer(port: proxyPort)
        let runningProxy = RunningProxy(server: proxy)
        try runningProxy.start()
        defer { runningProxy.stop() }

        var heldSlots = 0
        for _ in 0..<proxyMaxActiveConnections {
            XCTAssertTrue(proxy.admitConnectionForTesting())
            heldSlots += 1
        }
        defer {
            for _ in 0..<heldSlots {
                proxy.finishAdmittedConnectionForTesting()
            }
        }

        let sockets = try TCPTestSocket.socketPair()
        defer { close(sockets.client) }
        let finished = DispatchSemaphore(value: 0)
        let admittedLock = NSLock()
        var admitted: Bool?
        runDetached {
            let result = proxy.admitConnectionForTesting(sockets.server)
            admittedLock.lock()
            admitted = result
            admittedLock.unlock()
            close(sockets.server)
            finished.signal()
        }
        eventually(timeout: 1) {
            proxy.connectionAdmissionStats.queued == 1
        }

        proxy.stopAdmissionForTesting()

        XCTAssertEqual(finished.wait(timeout: .now() + 2), .success)
        admittedLock.lock()
        let admittedResult = admitted
        admittedLock.unlock()
        XCTAssertEqual(admittedResult, false)
        let response = try TCPTestSocket.readHTTPMessage(from: sockets.client, timeoutSeconds: 2)
        let text = String(data: response, encoding: .utf8) ?? ""

        XCTAssertTrue(text.contains("HTTP/1.1 503 Service Unavailable"), TCPTestSocket.describeResponse(text))
        XCTAssertTrue(text.contains(#""error": "Service Unavailable""#), TCPTestSocket.describeResponse(text))
    }

    private func eventually(
        timeout: TimeInterval,
        file: StaticString = #filePath,
        line: UInt = #line,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTFail("condition not satisfied before timeout", file: file, line: line)
    }

    private func providerPEMFixture(label: String, payload: String) -> String {
        "-----BEGIN \(label)-----\n\(payload)\n-----END \(label)-----"
    }
}

private final class RunningProxy {
    private let server: ProxyServer
    private let started = DispatchSemaphore(value: 0)
    private let stopped = DispatchSemaphore(value: 0)
    private var startError: Error?

    init(server: ProxyServer) {
        self.server = server
    }

    func start() throws {
        runDetached {
            do {
                try self.server.start {
                    self.started.signal()
                }
            } catch {
                self.startError = error
                self.started.signal()
            }
            self.stopped.signal()
        }
        guard started.wait(timeout: .now() + 3) == .success else {
            throw ProxyHarnessError.timeout("proxy did not start")
        }
        if let startError { throw startError }
    }

    func stop() {
        server.stop()
        _ = stopped.wait(timeout: .now() + 3)
    }
}

private final class LockedValue<Value> {
    private let lock = NSLock()
    private var storage: Value

    init(_ value: Value) {
        storage = value
    }

    var value: Value {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func set(_ value: Value) {
        lock.lock()
        storage = value
        lock.unlock()
    }
}

private func captureStandardError(_ body: () throws -> Void) throws -> String {
    var fds = [Int32](repeating: 0, count: 2)
    guard pipe(&fds) == 0 else { throw ProxyHarnessError.systemError("pipe") }
    let savedStderr = dup(STDERR_FILENO)
    guard savedStderr >= 0 else {
        close(fds[0])
        close(fds[1])
        throw ProxyHarnessError.systemError("dup")
    }

    fflush(stderr)
    guard dup2(fds[1], STDERR_FILENO) >= 0 else {
        close(fds[0])
        close(fds[1])
        close(savedStderr)
        throw ProxyHarnessError.systemError("dup2")
    }
    close(fds[1])

    var restored = false
    func restoreStderr() {
        guard !restored else { return }
        fflush(stderr)
        dup2(savedStderr, STDERR_FILENO)
        close(savedStderr)
        restored = true
    }

    do {
        try body()
        restoreStderr()
        let data = try readPipeToEOF(fds[0])
        close(fds[0])
        return String(data: data, encoding: .utf8) ?? ""
    } catch {
        restoreStderr()
        close(fds[0])
        throw error
    }
}

private func readPipeToEOF(_ fd: Int32) throws -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = read(fd, &buffer, buffer.count)
        if n > 0 {
            data.append(contentsOf: buffer[0..<n])
        } else if n == 0 {
            return data
        } else if errno != EINTR {
            throw ProxyHarnessError.systemError("read")
        }
    }
}

private struct StubHTTPResponse {
    let status: Int
    let headers: [String: String]
    let body: Data
}

private final class StubHTTPServer {
    typealias Handler = (Data) -> StubHTTPResponse

    private let handler: Handler
    private let lock = NSLock()
    private var listenSocket: Int32 = -1
    private var isRunning = false
    private var handledRequests = 0

    private(set) var port: UInt16 = 0
    var requestCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return handledRequests
    }

    init(handler: @escaping Handler) throws {
        self.handler = handler
    }

    func start() throws {
        listenSocket = try TCPTestSocket.listenOnLoopback(port: 0)
        port = try TCPTestSocket.boundPort(for: listenSocket)
        isRunning = true
        let acceptSocket = listenSocket
        runDetached {
            self.acceptLoop(listenSocket: acceptSocket)
        }
    }

    func stop() {
        lock.lock()
        isRunning = false
        let fd = listenSocket
        let portToWake = port
        listenSocket = -1
        lock.unlock()
        if fd >= 0 {
            TCPTestSocket.wakeLoopbackListener(port: portToWake)
            close(fd)
        }
    }

    private func acceptLoop(listenSocket: Int32) {
        // WO-262: mirror ProxyServer.start(); stop() owns the mutable property,
        // while the accept loop uses an immutable fd captured at listener startup.
        while running {
            var addr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let client = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(listenSocket, sockPtr, &len)
                }
            }
            guard client >= 0 else { continue }
            guard running else {
                close(client)
                break
            }
            runDetached {
                self.handle(client)
            }
        }
    }

    private var running: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isRunning
    }

    private func handle(_ client: Int32) {
        defer { close(client) }
        guard let request = try? TCPTestSocket.readHTTPMessage(from: client, timeoutSeconds: 5) else {
            return
        }
        lock.lock()
        handledRequests += 1
        lock.unlock()
        let response = handler(request)
        var head = "HTTP/1.1 \(response.status) \(CurlHTTPClient.httpReasonPhrase(for: response.status))\r\n"
        for (key, value) in response.headers {
            head += "\(key): \(value)\r\n"
        }
        head += "Content-Length: \(response.body.count)\r\nConnection: close\r\n\r\n"
        var data = Data(head.utf8)
        data.append(response.body)
        try? TCPTestSocket.writeAll(data, to: client)
    }
}

private enum TCPTestSocket {
    static let validAnthropicMessagesBody = #"{"model":"claude-3","messages":[{"role":"user","content":"hello"}]}"#

    static func postRequest(path: String, body: String = "{}") -> String {
        request(method: "POST", path: path, body: body)
    }

    // WO-422: real-socket tests exercise method admission independently from POST helpers.
    static func request(method: String, path: String, body: String) -> String {
        let bodyData = Data(body.utf8)
        return """
        \(method) \(path) HTTP/1.1\r
        Host: 127.0.0.1\r
        Content-Type: application/json\r
        Content-Length: \(bodyData.count)\r
        \r
        \(body)
        """
    }

    static func postRequestData(path: String, body: Data, contentType: String = "application/json") -> Data {
        let head = "POST \(path) HTTP/1.1\r\n" +
            "Host: 127.0.0.1\r\n" +
            "Content-Type: \(contentType)\r\n" +
            "Content-Length: \(body.count)\r\n\r\n"
        var request = Data(head.utf8)
        request.append(body)
        return request
    }

    static func reserveLoopbackPort() throws -> UInt16 {
        let fd = try listenOnLoopback(port: 0)
        defer { close(fd) }
        return try boundPort(for: fd)
    }

    static func listenOnLoopback(port: UInt16) throws -> Int32 {
        let fd = socket(AF_INET, testSocketStreamType, 0)
        guard fd >= 0 else { throw ProxyHarnessError.systemError("socket") }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            close(fd)
            throw ProxyHarnessError.systemError("bind")
        }
        guard listen(fd, 128) == 0 else {
            close(fd)
            throw ProxyHarnessError.systemError("listen")
        }
        return fd
    }

    static func boundPort(for fd: Int32) throws -> UInt16 {
        var addr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                getsockname(fd, sockPtr, &len)
            }
        }
        guard result == 0 else { throw ProxyHarnessError.systemError("getsockname") }
        return UInt16(bigEndian: addr.sin_port)
    }

    static func wakeLoopbackListener(port: UInt16) {
        // WO-330: mirror ProxyServer.stop() so Linux CI does not leak blocked
        // accept-loop threads between real-socket harness tests.
        let fd = socket(AF_INET, testSocketStreamType, 0)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    static func socketPair() throws -> (client: Int32, server: Int32) {
        var sockets = [Int32](repeating: 0, count: 2)
        let result = socketpair(AF_UNIX, testSocketStreamType, 0, &sockets)
        guard result == 0 else { throw ProxyHarnessError.systemError("socketpair") }
        return (sockets[0], sockets[1])
    }

    static func roundTrip(port: UInt16, request: String, timeoutSeconds: Int = 3) throws -> String {
        return try roundTrip(port: port, requestData: Data(request.utf8), timeoutSeconds: timeoutSeconds)
    }

    static func roundTrip(port: UInt16, requestData: Data, timeoutSeconds: Int = 3) throws -> String {
        let fd = socket(AF_INET, testSocketStreamType, 0)
        guard fd >= 0 else { throw ProxyHarnessError.systemError("socket") }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { throw ProxyHarnessError.systemError("connect") }
        try writeAll(requestData, to: fd)
        let data = try readToEOF(from: fd, timeoutSeconds: timeoutSeconds)
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func describeResponse(_ response: String) -> String {
        // WO-319: Linux XCTest logs multiline assertion messages poorly; keep
        // real-socket harness failures as a single escaped line with length.
        let escaped = response
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "response_bytes=\(response.utf8.count) response=\(escaped)"
    }

    static func readHTTPMessage(from fd: Int32, timeoutSeconds: Int) throws -> Data {
        setReceiveTimeout(on: fd, seconds: timeoutSeconds)
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = recv(fd, &buffer, buffer.count, 0)
            if n < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    // WO-319: a recv timeout is not EOF; keep the harness deadline explicit.
                    guard Date() < deadline else {
                        throw ProxyHarnessError.timeout("timed out reading HTTP message")
                    }
                    Thread.sleep(forTimeInterval: 0.01)
                    continue
                }
                // WO-319: reset after bytes is an EOF-equivalent for the socket harness.
                if errno == ECONNRESET && !data.isEmpty { break }
                throw ProxyHarnessError.systemError("recv")
            }
            guard n > 0 else { break }
            data.append(contentsOf: buffer[0..<n])
            if let headerEnd = data.range(of: Data("\r\n\r\n".utf8))?.upperBound {
                let header = String(data: data[..<headerEnd], encoding: .utf8) ?? ""
                let length = header
                    .components(separatedBy: "\r\n")
                    .compactMap { line -> Int? in
                        guard line.lowercased().hasPrefix("content-length:") else { return nil }
                        return Int(line.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces))
                    }
                    .first ?? 0
                if data.count >= headerEnd + length { break }
            }
        }
        return data
    }

    static func readToEOF(from fd: Int32, timeoutSeconds: Int) throws -> Data {
        setReceiveTimeout(on: fd, seconds: timeoutSeconds)
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = recv(fd, &buffer, buffer.count, 0)
            if n > 0 {
                data.append(contentsOf: buffer[0..<n])
                continue
            }
            if n == 0 { break }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                // WO-319: Linux CI can report EAGAIN before proxy bytes arrive.
                guard Date() < deadline else {
                    throw ProxyHarnessError.timeout("timed out reading response")
                }
                Thread.sleep(forTimeInterval: 0.01)
                continue
            }
            // WO-319: reset after a response body is still a completed round trip.
            if errno == ECONNRESET && !data.isEmpty { break }
            throw ProxyHarnessError.systemError("recv")
        }
        return data
    }

    static func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let written = send(fd, base.advanced(by: offset), data.count - offset, 0)
                guard written > 0 else { throw ProxyHarnessError.systemError("send") }
                offset += written
            }
        }
    }

    private static func setReceiveTimeout(on fd: Int32, seconds: Int) {
        var timeout = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }
}

private func runDetached(_ work: @escaping () -> Void) {
    // WO-319: use real threads for blocking sockets so Linux CI does not rely on
    // DispatchQueue.global() overcommit behavior while clients wait for EOF.
    Thread.detachNewThread(work)
}

private enum ProxyHarnessError: Error, CustomStringConvertible {
    case posix(String, Int32)
    case timeout(String)

    static func systemError(_ op: String) -> ProxyHarnessError {
        .posix(op, errno)
    }

    var description: String {
        switch self {
        case .posix(let op, let code):
            return "\(op) failed with errno \(code)"
        case .timeout(let message):
            return message
        }
    }
}

#if canImport(Darwin)
private let testSocketStreamType = SOCK_STREAM
#else
private let testSocketStreamType = Int32(SOCK_STREAM.rawValue)
#endif
