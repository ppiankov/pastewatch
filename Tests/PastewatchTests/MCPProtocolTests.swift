import XCTest
@testable import PastewatchCore

final class MCPProtocolTests: XCTestCase {

    // MARK: - JSONValue encoding/decoding

    func testJSONValueStringEncodingDecoding() throws {
        let value = JSONValue.string("hello")
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueNumberEncodingDecoding() throws {
        let value = JSONValue.number(42.5)
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueBoolEncodingDecoding() throws {
        let trueValue = JSONValue.bool(true)
        let trueData = try JSONEncoder().encode(trueValue)
        let trueDecoded = try JSONDecoder().decode(JSONValue.self, from: trueData)
        XCTAssertEqual(trueDecoded, trueValue)

        let falseValue = JSONValue.bool(false)
        let falseData = try JSONEncoder().encode(falseValue)
        let falseDecoded = try JSONDecoder().decode(JSONValue.self, from: falseData)
        XCTAssertEqual(falseDecoded, falseValue)
    }

    func testJSONValueNullEncodingDecoding() throws {
        let value = JSONValue.null
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueArrayEncodingDecoding() throws {
        let value = JSONValue.array([
            .string("a"),
            .number(1),
            .bool(true),
            .null
        ])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    func testJSONValueObjectEncodingDecoding() throws {
        let value = JSONValue.object([
            "name": .string("test"),
            "count": .number(3),
            "active": .bool(false)
        ])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        XCTAssertEqual(decoded, value)
    }

    // MARK: - JSONRPCRequest decoding

    func testJSONRPCRequestDecoding() throws {
        let json = """
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }
        }
        """
        let data = Data(json.utf8)
        let request = try JSONDecoder().decode(JSONRPCRequest.self, from: data)

        XCTAssertEqual(request.jsonrpc, "2.0")
        XCTAssertEqual(request.id, .int(1))
        XCTAssertEqual(request.method, "initialize")

        guard case .object(let params) = request.params else {
            XCTFail("Expected object params")
            return
        }
        XCTAssertEqual(params["protocolVersion"], .string("2024-11-05"))
    }

    // MARK: - JSONRPCResponse encoding

    func testJSONRPCResponseEncoding() throws {
        let response = JSONRPCResponse(
            jsonrpc: "2.0",
            id: .int(1),
            result: .object([
                "protocolVersion": .string("2024-11-05"),
                "serverInfo": .object([
                    "name": .string("pastewatch-cli"),
                    "version": .string("0.4.0")
                ])
            ]),
            error: nil
        )

        let data = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(JSONRPCResponse.self, from: data)

        XCTAssertEqual(decoded.jsonrpc, "2.0")
        XCTAssertEqual(decoded.id, .int(1))
        XCTAssertNil(decoded.error)

        guard case .object(let result) = decoded.result else {
            XCTFail("Expected object result")
            return
        }
        XCTAssertEqual(result["protocolVersion"], .string("2024-11-05"))
    }

    // MARK: - JSONRPCId variants

    func testJSONRPCIdIntDecoding() throws {
        let json = Data("""
        {"jsonrpc":"2.0","id":42,"method":"test","params":null}
        """.utf8)
        let request = try JSONDecoder().decode(JSONRPCRequest.self, from: json)
        XCTAssertEqual(request.id, .int(42))
    }

    func testJSONRPCIdStringDecoding() throws {
        let json = Data("""
        {"jsonrpc":"2.0","id":"req-1","method":"test","params":null}
        """.utf8)
        let request = try JSONDecoder().decode(JSONRPCRequest.self, from: json)
        XCTAssertEqual(request.id, .string("req-1"))
    }
}
