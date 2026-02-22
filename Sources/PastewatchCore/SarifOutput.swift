import Foundation

// MARK: - SARIF 2.1.0 Codable structs

public struct SarifLog: Codable {
    public let schema: String
    public let version: String
    public let runs: [SarifRun]

    enum CodingKeys: String, CodingKey {
        case schema = "$schema"
        case version
        case runs
    }
}

public struct SarifRun: Codable {
    public let tool: SarifTool
    public let results: [SarifResult]
}

public struct SarifTool: Codable {
    public let driver: SarifDriver
}

public struct SarifDriver: Codable {
    public let name: String
    public let version: String
    public let informationUri: String
    public let rules: [SarifRule]
}

public struct SarifRule: Codable {
    public let id: String
    public let shortDescription: SarifMessage
    public let defaultConfiguration: SarifRuleConfig
    public let properties: SarifRuleProps?
}

public struct SarifRuleConfig: Codable {
    public let level: String
}

public struct SarifRuleProps: Codable {
    public let tags: [String]?
}

public struct SarifResult: Codable {
    public let ruleId: String
    public let level: String
    public let message: SarifMessage
    public let locations: [SarifLocation]?
}

public struct SarifMessage: Codable {
    public let text: String
}

public struct SarifLocation: Codable {
    public let physicalLocation: SarifPhysicalLocation
}

public struct SarifPhysicalLocation: Codable {
    public let artifactLocation: SarifArtifactLocation
    public let region: SarifRegion?
}

public struct SarifArtifactLocation: Codable {
    public let uri: String
}

public struct SarifRegion: Codable {
    public let startLine: Int
}

// MARK: - Formatter

public struct SarifFormatter {

    /// Format matches from a single source into SARIF JSON.
    public static func format(
        matches: [DetectedMatch],
        filePath: String?,
        version: String
    ) -> Data {
        let rules = buildRuleDefinitions()
        let results = buildResults(matches: matches, filePath: filePath)
        return encode(rules: rules, results: results, version: version)
    }

    /// Format matches from multiple files into a single SARIF run.
    public static func formatMultiFile(
        fileResults: [(filePath: String, matches: [DetectedMatch])],
        version: String
    ) -> Data {
        let rules = buildRuleDefinitions()
        var results: [SarifResult] = []
        for (filePath, matches) in fileResults {
            results.append(contentsOf: buildResults(matches: matches, filePath: filePath))
        }
        return encode(rules: rules, results: results, version: version)
    }

    // MARK: - Private

    private static func ruleId(for type: SensitiveDataType) -> String {
        "pastewatch/" + type.rawValue.uppercased().replacingOccurrences(of: " ", with: "_")
    }

    private static func customRuleId(name: String) -> String {
        "pastewatch/CUSTOM_" + name.uppercased().replacingOccurrences(of: " ", with: "_")
    }

    private static func buildRuleDefinitions() -> [SarifRule] {
        SensitiveDataType.allCases.map { type in
            SarifRule(
                id: ruleId(for: type),
                shortDescription: SarifMessage(text: "\(type.rawValue) detected"),
                defaultConfiguration: SarifRuleConfig(level: "error"),
                properties: SarifRuleProps(tags: ["security", "sensitive-data"])
            )
        }
    }

    private static func buildResults(
        matches: [DetectedMatch],
        filePath: String?
    ) -> [SarifResult] {
        matches.map { match in
            let id: String
            if let customName = match.customRuleName {
                id = customRuleId(name: customName)
            } else {
                id = ruleId(for: match.type)
            }

            let uri = filePath ?? match.filePath ?? "stdin"

            return SarifResult(
                ruleId: id,
                level: "error",
                message: SarifMessage(text: "\(match.displayName) detected"),
                locations: [
                    SarifLocation(
                        physicalLocation: SarifPhysicalLocation(
                            artifactLocation: SarifArtifactLocation(uri: uri),
                            region: SarifRegion(startLine: match.line)
                        )
                    )
                ]
            )
        }
    }

    private static func encode(
        rules: [SarifRule],
        results: [SarifResult],
        version: String
    ) -> Data {
        let log = SarifLog(
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: [
                SarifRun(
                    tool: SarifTool(
                        driver: SarifDriver(
                            name: "pastewatch-cli",
                            version: version,
                            informationUri: "https://github.com/ppiankov/pastewatch",
                            rules: rules
                        )
                    ),
                    results: results
                )
            ]
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        // swiftlint:disable:next force_try
        return try! encoder.encode(log)
    }
}
