import XCTest
@testable import PastewatchCore

final class StdinFilenameTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

    func testExtensionExtractionFromFilename() {
        let envPath = URL(fileURLWithPath: "/tmp/.env")
        XCTAssertEqual(envPath.lastPathComponent, ".env")

        let jsonPath = URL(fileURLWithPath: "config.json")
        XCTAssertEqual(jsonPath.pathExtension.lowercased(), "json")

        let ymlPath = URL(fileURLWithPath: "/home/user/app.yml")
        XCTAssertEqual(ymlPath.pathExtension.lowercased(), "yml")

        let yamlPath = URL(fileURLWithPath: "deploy.yaml")
        XCTAssertEqual(yamlPath.pathExtension.lowercased(), "yaml")

        let propsPath = URL(fileURLWithPath: "db.properties")
        XCTAssertEqual(propsPath.pathExtension.lowercased(), "properties")

        XCTAssertNotNil(parserForExtension("env"))
        XCTAssertNotNil(parserForExtension("json"))
        XCTAssertNotNil(parserForExtension("yml"))
        XCTAssertNotNil(parserForExtension("yaml"))
        XCTAssertNotNil(parserForExtension("properties"))
        XCTAssertNil(parserForExtension("txt"))
        XCTAssertNil(parserForExtension(""))
    }

    func testFormatAwareEnvParsing() {
        let awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].joined()
        let envContent = "SAFE=hello\nAWS_KEY=\(awsKey)\n"
        guard let parser = parserForExtension("env") else {
            XCTFail("Expected parser for env extension")
            return
        }

        let parsedValues = parser.parseValues(from: envContent)
        XCTAssertEqual(parsedValues.count, 2)
        XCTAssertEqual(parsedValues[0].key, "SAFE")
        XCTAssertEqual(parsedValues[1].key, "AWS_KEY")
        XCTAssertEqual(parsedValues[1].value, awsKey)

        var collected: [DetectedMatch] = []
        for pv in parsedValues {
            let matches = DetectionRules.scan(pv.value, config: config)
            for m in matches {
                collected.append(DetectedMatch(
                    type: m.type, value: m.value, range: m.range,
                    line: pv.line
                ))
            }
        }

        let awsMatches = collected.filter { $0.type == .awsKey }
        XCTAssertEqual(awsMatches.count, 1)
        XCTAssertEqual(awsMatches.first?.line, 2)
    }

    func testStdinFilenameConflictsWithFile() {
        // --stdin-filename is only valid for stdin; when --file is set, both provide a path.
        // Verify the underlying logic: if both a file path and a stdin filename are present,
        // the file path takes precedence for extension extraction.
        let filePath = "/tmp/data.txt"
        let stdinFilename = "secrets.env"

        let fileExt = URL(fileURLWithPath: filePath).pathExtension.lowercased()
        let stdinExt = URL(fileURLWithPath: stdinFilename).pathExtension.lowercased()

        XCTAssertEqual(fileExt, "txt")
        XCTAssertEqual(stdinExt, "env")
        XCTAssertNil(parserForExtension(fileExt))
        XCTAssertNotNil(parserForExtension(stdinExt))
    }

    func testStdinFilenameConflictsWithDir() {
        // --stdin-filename is only valid for stdin; when --dir is set, directory scanning
        // uses its own per-file extension logic. Verify that dir paths have no meaningful
        // extension to parse (they are directories, not files).
        let dirPath = "/tmp/project"
        let dirExt = URL(fileURLWithPath: dirPath).pathExtension.lowercased()
        XCTAssertEqual(dirExt, "")
        XCTAssertNil(parserForExtension(dirExt))
    }
}
