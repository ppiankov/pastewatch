import XCTest
@testable import PastewatchCore

final class MutationAuthorizationTests: XCTestCase {
    private let config = PastewatchConfig.defaultConfig

    func testIntrinsicAuthorizationSetIsExplicit() {
        // WO-454: this literal set makes detector promotion a reviewed policy change.
        let expected: Set<SensitiveDataType> = [
            .awsKey, .genericApiKey, .sshPrivateKey, .jwtToken, .creditCard,
            .slackWebhook, .discordWebhook, .azureConnectionString, .gcpServiceAccount,
            .openaiKey, .anthropicKey, .huggingfaceToken, .groqKey, .npmToken,
            .pypiToken, .rubygemsToken, .gitlabToken, .telegramBotToken, .sendgridKey,
            .shopifyToken, .digitaloceanToken, .perplexityKey, .workledgerKey,
            .oraculKey, .obstalabsKey, .resendKey, .vaultToken, .slackToken,
            .googleApiKey, .dockerAccessToken, .githubToken,
        ]

        XCTAssertEqual(
            Set(SensitiveDataType.allCases.filter(\.intrinsicMutationAuthorized)),
            expected
        )
        XCTAssertFalse(SensitiveDataType.dbConnectionString.intrinsicMutationAuthorized)
        XCTAssertFalse(SensitiveDataType.jdbcUrl.intrinsicMutationAuthorized)
        XCTAssertFalse(SensitiveDataType.credential.intrinsicMutationAuthorized)
    }

    func testPartitionConservesEveryMatchAndSeverityDoesNotAuthorize() {
        let dsn = "postgres" + "://user:example@localhost/db"
        let text = dsn + " AIza" + String(repeating: "A", count: 35)
        let matches = DetectionRules.scan(text, config: config)
        let partition = partitionMutationMatches(
            matches,
            site: .proxyUserText,
            minAdvisorySeverity: .critical
        )

        XCTAssertEqual(
            partition.authorized.count + partition.advisory.count + partition.advisoryBelowThreshold.count,
            matches.count
        )
        XCTAssertTrue(partition.authorized.contains { $0.type == .googleApiKey })
        XCTAssertTrue(partition.advisory.contains { $0.type == .dbConnectionString })
    }

    func testExactKnownValueAuthorizesFormatOnlyMatch() {
        let value = "postgres" + "://user:example@localhost/db"
        let matches = DetectionRules.scan(
            value,
            config: config,
            knownSecretValues: [value]
        )

        XCTAssertEqual(matches.count, 1)
        XCTAssertTrue(matches[0].mutationAuthorizationSources.contains(.exactKnownSecret))
        let outcome = applyAuthorizedMutations(
            to: value,
            matches: matches,
            site: .proxyInputSchema,
            minAdvisorySeverity: .critical
        )
        XCTAssertFalse(outcome.text.contains(value))
    }

    func testCustomRuleAuthorizationSurvivesBuiltInOverlap() throws {
        let value = "postgres" + "://user:example@localhost/db"
        let rule = CustomRule(
            name: "Approved DSN",
            regex: try NSRegularExpression(pattern: NSRegularExpression.escapedPattern(for: value)),
            severity: .low,
            type: .dbConnectionString
        )
        let matches = DetectionRules.scan(value, config: config, customRules: [rule])

        XCTAssertEqual(matches.count, 1)
        XCTAssertTrue(matches[0].mutationAuthorizationSources.contains(.customRule))
        let outcome = applyAuthorizedMutations(
            to: value,
            matches: matches,
            site: .proxyToolDescription,
            minAdvisorySeverity: .critical
        )
        XCTAssertEqual(outcome.mutated.count, 1)
        XCTAssertFalse(outcome.text.contains(value))
    }

    func testProxyUsesEvidenceAcrossRequestSites() throws {
        let token = "AIza" + String(repeating: "K", count: 35)
        let dsn = "postgres" + "://user:example@localhost/db"
        let body = """
        {"system":"\(dsn)","tools":[{"name":"lookup","description":"\(dsn)","input_schema":{"type":"object","default":"\(dsn)"},"input_examples":[{"token":"\(token)","dsn":"\(dsn)"}]}],"stop_sequences":["\(token)"],"messages":[{"role":"user","content":"\(dsn) \(token)"},{"role":"assistant","content":[{"type":"tool_use","id":"x","name":"lookup","input":{"token":"\(token)","dsn":"\(dsn)"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":"\(token) \(dsn)"}]}]}
        """

        let result = ProxyServer(port: 0).scanAndRedactBody(body)
        XCTAssertGreaterThan(result.redacted, 0)
        XCTAssertGreaterThan(result.advisoryCount, 0)
        XCTAssertFalse(result.body.contains(token))

        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any]
        )
        let tools = try XCTUnwrap(json["tools"] as? [[String: Any]])
        XCTAssertEqual(json["system"] as? String, dsn)
        let examples = try XCTUnwrap(tools[0]["input_examples"] as? [[String: Any]])
        XCTAssertEqual(examples[0]["dsn"] as? String, dsn)
        XCTAssertNotEqual(examples[0]["token"] as? String, token)
    }

    func testEveryMutationSiteUsesTheSameEvidenceGate() {
        let token = "AIza" + String(repeating: "L", count: 35)
        let matches = DetectionRules.scan(token, config: config)

        for site in MutationSite.allCases {
            let outcome = applyAuthorizedMutations(
                to: token,
                matches: matches,
                site: site,
                minAdvisorySeverity: .critical
            )
            XCTAssertEqual(outcome.mutated.count, 1, "site \(site) bypassed authorization")
            XCTAssertFalse(outcome.text.contains(token), "site \(site) leaked authorized bytes")
        }
    }

    func testProductionMutationUsesOnlyTheAuthorizationGateway() throws {
        // WO-454: raw obfuscation remains a compatibility API, so CI enforces the
        // production call graph while redactForDisplay stays the named exception.
        let testFile = URL(fileURLWithPath: #filePath)
        let repository = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sources = repository.appendingPathComponent("Sources")
        let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
        var callers: [String] = []

        for case let fileURL as URL in enumerator where fileURL.pathExtension == "swift" {
            let source = try String(contentsOf: fileURL, encoding: .utf8)
            if source.contains("Obfuscator.obfuscate(") {
                callers.append(fileURL.lastPathComponent)
            }
        }

        XCTAssertEqual(callers, ["MutationAuthorization.swift"])
    }
}
