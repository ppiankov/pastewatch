import XCTest
@testable import PastewatchCore

final class SarifOutputTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

    func testSarifStructure() {
        let content = "Contact test@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: nil, version: "0.3.0")

        let json = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["version"] as? String, "2.1.0")
        XCTAssertNotNil(json["$schema"])

        let runs = json["runs"] as! [[String: Any]]
        XCTAssertEqual(runs.count, 1)

        let tool = runs[0]["tool"] as! [String: Any]
        let driver = tool["driver"] as! [String: Any]
        XCTAssertEqual(driver["name"] as? String, "pastewatch-cli")
    }

    func testSarifResults() {
        let content = "Email: test@corp.com and IP 10.0.0.1"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: "test.txt", version: "0.3.0")

        let json = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        let runs = json["runs"] as! [[String: Any]]
        let results = runs[0]["results"] as! [[String: Any]]

        XCTAssertEqual(results.count, matches.count)

        // Check first result has required fields
        let firstResult = results[0]
        XCTAssertNotNil(firstResult["ruleId"])
        XCTAssertNotNil(firstResult["message"])
        XCTAssertNotNil(firstResult["locations"])
    }

    func testSarifRuleIds() {
        let content = "test@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: nil, version: "0.3.0")

        let json = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        let runs = json["runs"] as! [[String: Any]]
        let results = runs[0]["results"] as! [[String: Any]]

        XCTAssertEqual(results[0]["ruleId"] as? String, "pastewatch/EMAIL")
    }

    func testSarifLineNumbers() {
        let content = "clean line\ntest@corp.com on line 2"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: "test.txt", version: "0.3.0")

        let json = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        let runs = json["runs"] as! [[String: Any]]
        let results = runs[0]["results"] as! [[String: Any]]
        let locations = results[0]["locations"] as! [[String: Any]]
        let physical = locations[0]["physicalLocation"] as! [String: Any]
        let region = physical["region"] as! [String: Any]

        XCTAssertEqual(region["startLine"] as? Int, 2)
    }

    func testSarifStdinUri() {
        let content = "test@corp.com"
        let matches = DetectionRules.scan(content, config: config)
        let data = SarifFormatter.format(matches: matches, filePath: nil, version: "0.3.0")

        let json = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        let runs = json["runs"] as! [[String: Any]]
        let results = runs[0]["results"] as! [[String: Any]]
        let locations = results[0]["locations"] as! [[String: Any]]
        let physical = locations[0]["physicalLocation"] as! [String: Any]
        let artifact = physical["artifactLocation"] as! [String: Any]

        XCTAssertEqual(artifact["uri"] as? String, "stdin")
    }

    func testSarifNoFindings() {
        let data = SarifFormatter.format(matches: [], filePath: nil, version: "0.3.0")

        let json = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        let runs = json["runs"] as! [[String: Any]]
        let results = runs[0]["results"] as! [[String: Any]]

        XCTAssertEqual(results.count, 0)
    }
}
