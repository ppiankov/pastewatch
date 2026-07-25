import XCTest
@testable import PastewatchCore

final class SarifOutputTests: XCTestCase {
    // WO-542: SARIF fixtures opt in to the ambiguous classes whose formatting they exercise.
    let config: PastewatchConfig = {
        var config = TestConfigHelper.configWithEmailObfuscation()
        config.enabledTypes.append(SensitiveDataType.ipAddress.rawValue)
        return config
    }()

    func testSarifStructure() throws {
        let content = "Contact test@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: nil, version: "0.3.0")

        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["version"] as? String, "2.1.0")
        XCTAssertNotNil(json["$schema"])

        let runs = try XCTUnwrap(json["runs"] as? [[String: Any]])
        XCTAssertEqual(runs.count, 1)

        let tool = try XCTUnwrap(runs[0]["tool"] as? [String: Any])
        let driver = try XCTUnwrap(tool["driver"] as? [String: Any])
        XCTAssertEqual(driver["name"] as? String, "pastewatch-cli")
    }

    func testSarifResults() throws {
        let content = "Email: test@corp.com and IP 10.0.0.1"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: "test.txt", version: "0.3.0")

        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let runs = try XCTUnwrap(json["runs"] as? [[String: Any]])
        let results = try XCTUnwrap(runs[0]["results"] as? [[String: Any]])

        XCTAssertEqual(results.count, matches.count)

        // WO-542: avoid positional traps while preserving SARIF assertions.
        let firstResult = try XCTUnwrap(results.first)
        XCTAssertNotNil(firstResult["ruleId"])
        XCTAssertNotNil(firstResult["message"])
        XCTAssertNotNil(firstResult["locations"])
    }

    func testSarifRuleIds() throws {
        let content = "test@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: nil, version: "0.3.0")

        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let runs = try XCTUnwrap(json["runs"] as? [[String: Any]])
        let results = try XCTUnwrap(runs[0]["results"] as? [[String: Any]])

        // WO-542: unwrap the configured email result before checking its rule ID.
        let firstResult = try XCTUnwrap(results.first)
        XCTAssertEqual(firstResult["ruleId"] as? String, "pastewatch/EMAIL")
    }

    func testSarifLineNumbers() throws {
        let content = "clean line\ntest@corp.com on line 2"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: "test.txt", version: "0.3.0")

        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let runs = try XCTUnwrap(json["runs"] as? [[String: Any]])
        let results = try XCTUnwrap(runs[0]["results"] as? [[String: Any]])
        // WO-542: unwrap nested SARIF arrays while retaining line-number coverage.
        let firstResult = try XCTUnwrap(results.first)
        let locations = try XCTUnwrap(firstResult["locations"] as? [[String: Any]])
        let firstLocation = try XCTUnwrap(locations.first)
        let physical = try XCTUnwrap(firstLocation["physicalLocation"] as? [String: Any])
        let region = try XCTUnwrap(physical["region"] as? [String: Any])

        XCTAssertEqual(region["startLine"] as? Int, 2)
    }

    func testSarifStdinUri() throws {
        let content = "test@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: nil, version: "0.3.0")

        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let runs = try XCTUnwrap(json["runs"] as? [[String: Any]])
        let results = try XCTUnwrap(runs[0]["results"] as? [[String: Any]])
        // WO-542: unwrap nested SARIF arrays while retaining stdin URI coverage.
        let firstResult = try XCTUnwrap(results.first)
        let locations = try XCTUnwrap(firstResult["locations"] as? [[String: Any]])
        let firstLocation = try XCTUnwrap(locations.first)
        let physical = try XCTUnwrap(firstLocation["physicalLocation"] as? [String: Any])
        let artifact = try XCTUnwrap(physical["artifactLocation"] as? [String: Any])

        XCTAssertEqual(artifact["uri"] as? String, "stdin")
    }

    func testSarifNoFindings() throws {
        let data = SarifFormatter.format(matches: [], filePath: nil, version: "0.3.0")

        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let runs = try XCTUnwrap(json["runs"] as? [[String: Any]])
        let results = try XCTUnwrap(runs[0]["results"] as? [[String: Any]])

        XCTAssertEqual(results.count, 0)
    }
}
