import XCTest
@testable import PastewatchCore

final class ProviderTokenPatternTests: XCTestCase {
    private struct Fixture {
        let type: SensitiveDataType
        let positive: String
        let negative: String
    }

    // WO-484: fixtures are synthetic and offline; none are usable credentials.
    private var fixtures: [Fixture] {
        [
            .init(type: .awsKey, positive: "AKIA" + String(repeating: "A", count: 16), negative: "AKIA" + String(repeating: "A", count: 15)),
            .init(type: .genericApiKey, positive: "sk_live_" + String(repeating: "B", count: 24), negative: "sk_live_" + String(repeating: "B", count: 23)),
            .init(type: .slackWebhook, positive: "https://hooks.slack.com/services/TABC/BDEF/Token123", negative: "https://hooks.slack.com/services/ABC/BDEF/Token123"),
            .init(type: .discordWebhook, positive: "https://discord.com/api/webhooks/123456/Token_123", negative: "https://discord.com/api/webhooks/id/Token_123"),
            .init(type: .openaiKey, positive: "sk-proj-" + String(repeating: "C", count: 20), negative: "sk-proj-" + String(repeating: "C", count: 19)),
            .init(type: .anthropicKey, positive: "sk-ant-api03-" + String(repeating: "D", count: 20), negative: "sk-ant-api03-" + String(repeating: "D", count: 19)),
            .init(type: .huggingfaceToken, positive: "hf_" + String(repeating: "E", count: 20), negative: "hf_" + String(repeating: "E", count: 19)),
            .init(type: .groqKey, positive: "gsk_" + String(repeating: "F", count: 20), negative: "gsk_" + String(repeating: "F", count: 19)),
            .init(type: .npmToken, positive: "npm_" + String(repeating: "G", count: 20), negative: "npm_" + String(repeating: "G", count: 19)),
            .init(type: .pypiToken, positive: "pypi-" + String(repeating: "H", count: 20), negative: "pypi-" + String(repeating: "H", count: 19)),
            .init(type: .rubygemsToken, positive: "rubygems_" + String(repeating: "I", count: 20), negative: "rubygems_" + String(repeating: "I", count: 19)),
            .init(type: .gitlabToken, positive: "glpat-" + String(repeating: "J", count: 20), negative: "glpat-" + String(repeating: "J", count: 19)),
            .init(type: .telegramBotToken, positive: "12345678:AA" + String(repeating: "K", count: 33), negative: "12345678:AA" + String(repeating: "K", count: 32)),
            .init(type: .sendgridKey, positive: "SG." + String(repeating: "L", count: 20) + "." + String(repeating: "M", count: 20), negative: "SG." + String(repeating: "L", count: 19) + "." + String(repeating: "M", count: 20)),
            .init(type: .shopifyToken, positive: "shpat_" + String(repeating: "a", count: 20), negative: "shpat_" + String(repeating: "a", count: 19)),
            .init(type: .digitaloceanToken, positive: "dop_v1_" + String(repeating: "b", count: 64), negative: "dop_v1_" + String(repeating: "b", count: 63)),
            .init(type: .perplexityKey, positive: "pplx-" + String(repeating: "N", count: 48), negative: "pplx-" + String(repeating: "N", count: 47)),
            .init(type: .workledgerKey, positive: "wl_sk_" + String(repeating: "O", count: 32), negative: "wl_sk_" + String(repeating: "O", count: 31)),
            .init(type: .oraculKey, positive: "vc_pro_" + String(repeating: "c", count: 32), negative: "vc_pro_" + String(repeating: "c", count: 31)),
            .init(type: .obstalabsKey, positive: "ol_" + String(repeating: "P", count: 20) + "." + String(repeating: "Q", count: 40), negative: "ol_" + String(repeating: "P", count: 19) + "." + String(repeating: "Q", count: 40)),
            .init(type: .resendKey, positive: "re_" + String(repeating: "R", count: 24), negative: "re_" + String(repeating: "R", count: 23)),
            .init(type: .vaultToken, positive: "hvs." + String(repeating: "S", count: 24), negative: "hvs." + String(repeating: "S", count: 23)),
            .init(type: .slackToken, positive: ["xox", "b-1234567890-"].joined() + String(repeating: "T", count: 24), negative: ["xox", "b-short"].joined()),
            .init(type: .googleApiKey, positive: "AIza" + String(repeating: "U", count: 35), negative: "AIza" + String(repeating: "U", count: 34)),
            .init(type: .dockerAccessToken, positive: "dckr_pat_" + String(repeating: "V", count: 15), negative: "dckr_pat_" + String(repeating: "V", count: 14)),
            .init(type: .githubToken, positive: "github_pat_" + String(repeating: "W", count: 20), negative: "github_pat_" + String(repeating: "W", count: 19)),
        ]
    }

    func testManifestCoversExplicitProviderDetectorSet() {
        let expected: Set<SensitiveDataType> = [
            .awsKey, .genericApiKey, .slackWebhook, .discordWebhook, .openaiKey,
            .anthropicKey, .huggingfaceToken, .groqKey, .npmToken, .pypiToken,
            .rubygemsToken, .gitlabToken, .telegramBotToken, .sendgridKey,
            .shopifyToken, .digitaloceanToken, .perplexityKey, .workledgerKey,
            .oraculKey, .obstalabsKey, .resendKey, .vaultToken, .slackToken,
            .googleApiKey, .dockerAccessToken, .githubToken,
        ]
        let manifest = DetectionRules.providerTokenPatternManifest

        XCTAssertEqual(Set(manifest.map(\.type)), expected)
        XCTAssertEqual(Set(fixtures.map(\.type)), expected)
        XCTAssertEqual(Set(manifest.map(\.fixtureID)).count, manifest.count)
        XCTAssertTrue(manifest.allSatisfy { $0.primarySource.hasPrefix("https://") })
        XCTAssertTrue(manifest.allSatisfy { $0.reviewedOn == "2026-07-15" })
    }

    func testProviderFixturesHavePositiveAndBoundaryNegativeCoverage() {
        for fixture in fixtures {
            let positive = DetectionRules.scan(fixture.positive, config: .defaultConfig)
            XCTAssertTrue(
                positive.contains {
                    $0.type == fixture.type
                        && $0.value == fixture.positive
                        && $0.mutationAuthorizationSources.contains(.intrinsicFormat)
                },
                "missing complete intrinsic match for \(fixture.type.rawValue)"
            )

            let negative = DetectionRules.scan(fixture.negative, config: .defaultConfig)
            XCTAssertFalse(
                negative.contains { $0.type == fixture.type },
                "boundary near-miss matched \(fixture.type.rawValue)"
            )
        }
    }

    func testUnsupportedIdentifiersRemainNonSecrets() {
        // WO-484: Twilio SK values are SIDs, not bearer secrets; Square EAAA lacks
        // a primary format guarantee and remains unsupported.
        let twilioSID = "SK" + String(repeating: "a", count: 32)
        let squareLookalike = "EAAA" + String(repeating: "B", count: 40)
        XCTAssertTrue(DetectionRules.scan(twilioSID, config: .defaultConfig).isEmpty)
        XCTAssertTrue(DetectionRules.scan(squareLookalike, config: .defaultConfig).isEmpty)
    }
}
