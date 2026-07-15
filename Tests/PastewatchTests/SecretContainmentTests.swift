import XCTest
@testable import PastewatchCore

final class SecretContainmentTests: XCTestCase {
    // WO-480: explicit fixtures make every mutation-authorized detector prove that
    // matched secret bytes disappear while surrounding bytes remain exact.
    private var fixtures: [SensitiveDataType: String] {
        [
            .awsKey: "AKIA" + String(repeating: "A", count: 16),
            .sshPrivateKey: "-----BEGIN " + "PRIVATE KEY-----\n" + String(repeating: "QUJD", count: 12) + "\n-----END PRIVATE KEY-----",
            .jwtToken: "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0In0." + String(repeating: "c", count: 32),
            .creditCard: "4111111111111111",
            .slackWebhook: "https://hooks.slack.com/services/TABC/BDEF/Token123",
            .discordWebhook: "https://discord.com/api/webhooks/123456/Token_123",
            .azureConnectionString: "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=abc123def456+ghi789==",
            .gcpServiceAccount: #"{"type":"service_account","private_key_id":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","private_key":"synthetic-private-material"}"#,
            .openaiKey: "sk-proj-" + String(repeating: "C", count: 20),
            .anthropicKey: "sk-ant-api03-" + String(repeating: "D", count: 20),
            .huggingfaceToken: "hf_" + String(repeating: "E", count: 20),
            .groqKey: "gsk_" + String(repeating: "F", count: 20),
            .npmToken: "npm_" + String(repeating: "G", count: 20),
            .pypiToken: "pypi-" + String(repeating: "H", count: 20),
            .rubygemsToken: "rubygems_" + String(repeating: "I", count: 20),
            .gitlabToken: "glpat-" + String(repeating: "J", count: 20),
            .telegramBotToken: "12345678:AA" + String(repeating: "K", count: 33),
            .sendgridKey: "SG." + String(repeating: "L", count: 20) + "." + String(repeating: "M", count: 20),
            .shopifyToken: "shpat_" + String(repeating: "a", count: 20),
            .digitaloceanToken: "dop_v1_" + String(repeating: "b", count: 64),
            .perplexityKey: "pplx-" + String(repeating: "N", count: 48),
            .workledgerKey: "wl_sk_" + String(repeating: "O", count: 32),
            .oraculKey: "vc_pro_" + String(repeating: "c", count: 32),
            .obstalabsKey: "ol_" + String(repeating: "P", count: 20) + "." + String(repeating: "Q", count: 40),
            .resendKey: "re_" + String(repeating: "R", count: 24),
            .vaultToken: "hvs." + String(repeating: "S", count: 24),
            .slackToken: ["xox", "b-1234567890-"].joined() + String(repeating: "T", count: 24),
            .googleApiKey: "AIza" + String(repeating: "U", count: 35),
            .dockerAccessToken: "dckr_pat_" + String(repeating: "V", count: 15),
            .githubToken: "github_pat_" + String(repeating: "W", count: 20),
        ]
    }

    // WO-487: these share the compatibility type but receive authorization from
    // their exact provider grammar rather than from the type itself.
    private var sourcedGenericFixtures: [String] {
        [
            "ghp_" + String(repeating: "B", count: 36),
            "sk_live_" + String(repeating: "C", count: 24),
            "whsec_" + String(repeating: "D", count: 24),
        ]
    }

    func testEveryAuthorizedDetectorContainsItsCompleteMatchedBytes() {
        let expected = Set(SensitiveDataType.allCases.filter(\.intrinsicMutationAuthorized))
        XCTAssertEqual(Set(fixtures.keys), expected)

        for (type, fixture) in fixtures {
            let isStructuredGCP = type == .gcpServiceAccount
            let content = isStructuredGCP ? fixture : "prefix|\(fixture)|suffix"
            let matches = DetectionRules.scan(content, config: .defaultConfig)
            let authorized = matches.filter {
                $0.type == type && $0.mutationAuthorizationSources.contains(.intrinsicFormat)
            }
            XCTAssertFalse(authorized.isEmpty, "missing fixture match for \(type.rawValue)")

            let outcome = applyAuthorizedMutations(
                to: content,
                matches: matches,
                site: .cliScan,
                minAdvisorySeverity: .low
            )
            for match in authorized {
                XCTAssertFalse(outcome.text.contains(match.value), "leaked \(type.rawValue) match")
            }
            if !isStructuredGCP {
                XCTAssertTrue(outcome.text.hasPrefix("prefix|"), "overcaptured prefix for \(type.rawValue)")
                XCTAssertTrue(outcome.text.hasSuffix("|suffix"), "overcaptured suffix for \(type.rawValue)")
            }
        }
    }

    func testMarkersAndPartialShapesNeverAuthorizeMutation() {
        let partials = [
            "AKIA" + String(repeating: "A", count: 15),
            "-----BEGIN " + "PRIVATE KEY-----\nQUJD",
            #"{"type":"service_account"}"#,
            "AIza" + String(repeating: "U", count: 34),
            "dckr_pat_" + String(repeating: "V", count: 14),
        ]

        for partial in partials {
            let matches = DetectionRules.scan(partial, config: .defaultConfig)
            XCTAssertTrue(
                partitionMutationMatches(matches, site: .cliScan, minAdvisorySeverity: .low)
                    .authorized.isEmpty,
                "partial shape authorized mutation"
            )
        }
    }

    func testSourcedGenericProviderGrammarsContainCompleteMatchedBytes() {
        for fixture in sourcedGenericFixtures {
            let content = "prefix|\(fixture)|suffix"
            let matches = DetectionRules.scan(content, config: .defaultConfig)
            let authorized = matches.filter {
                $0.type == .genericApiKey
                    && $0.mutationAuthorizationSources.contains(.intrinsicFormat)
            }
            XCTAssertEqual(authorized.count, 1)

            let outcome = applyAuthorizedMutations(
                to: content,
                matches: matches,
                site: .cliScan,
                minAdvisorySeverity: .low
            )
            XCTAssertFalse(outcome.text.contains(fixture))
            XCTAssertTrue(outcome.text.hasPrefix("prefix|"))
            XCTAssertTrue(outcome.text.hasSuffix("|suffix"))
        }
    }
}
