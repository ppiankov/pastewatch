import XCTest
@testable import PastewatchCore

// WO-657@v1: billing issues one signed two-part grammar; fixtures contain no signing key.
enum BillingLicenseFixture {
    // WO-657@v1: reproduce the versioned JSON envelope and the 64-byte Ed25519 wire length offline.
    static func makeSignedShape() throws -> String {
        let payload: [String: Any] = [
            "version": 2,
            "license_id": "lic_" + String(repeating: "a", count: 32),
            "subject": "fixture-buyer",
            "products": ["fixture-product"],
            "entitlements": [["product": "fixture-product", "tier": "fixture-tier"]],
            "plan": "fixture-tier",
            "issued_at": 1_700_000_000,
            "not_before": 1_700_000_000,
            "expires_at": 1_800_000_000,
            "issuer": "obstalabs-billing",
            "key_id": ["ol-", "ed25519-primary"].joined()
        ]
        let encoded = encodeBase64URL(try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
        let ed25519SignatureBytes = 64
        let signature = encodeBase64URL(Data(repeating: 0xfb, count: ed25519SignatureBytes))
        return ["o", "l_", encoded, ".", signature].joined()
    }

    // WO-657@v1: billing uses unpadded URL-safe base64 for both token parts.
    private static func encodeBase64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

final class ProviderTokenPatternTests: XCTestCase {
    // WO-657@v1: the billing-derived shape stays covered by the existing intrinsic manifest family.
    func testBillingSignedLicenseShapeHasIntrinsicProviderCoverage() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = try BillingLicenseFixture.makeSignedShape()
            let parts = value.dropFirst(3).split(separator: ".")
            XCTAssertEqual(parts.count, 2)
            XCTAssertGreaterThanOrEqual(parts[0].count, 20)
            XCTAssertEqual(parts[1].count, 86)
            XCTAssertFalse(value.contains("="))
            let manifest = DetectionRules.providerTokenPatternManifest.filter { $0.type == .obstalabsKey }
            XCTAssertEqual(manifest.count, 1)
            XCTAssertEqual(manifest.first?.fixtureID, "obstalabs-key")
            let matches = DetectionRules.scan(value, config: .defaultConfig)
            XCTAssertEqual(matches.count, 1)
            XCTAssertTrue(matches.first?.value == value)
            XCTAssertTrue(matches.first?.mutationAuthorizationSources.contains(.intrinsicFormat) == true)
            XCTAssertEqual(matches.first?.effectiveSeverity, .critical)
        }
    }

    // WO-657@v1: short parts, missing separators and prefix mentions cannot authorize provider mutation.
    func testBillingLicenseShapeNearMissesRemainNonSecrets() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let value = try BillingLicenseFixture.makeSignedShape()
            let parts = value.dropFirst(3).split(separator: ".").map(String.init)
            let prefix = ["o", "l_"].joined()
            let values = [
                prefix + String(parts[0].prefix(19)) + "." + parts[1],
                prefix + parts[0] + "." + String(parts[1].prefix(39)),
                prefix + parts[0] + ":" + parts[1],
                prefix + parts[0] + parts[1],
                "A license prefix is " + prefix + " in prose.",
                "x" + value
            ]
            for (index, candidate) in values.enumerated() {
                XCTAssertFalse(DetectionRules.scan(candidate, config: .defaultConfig).contains {
                    $0.type == .obstalabsKey
                }, "near-miss row \(index)")
            }
        }
    }

    private struct Fixture {
        let type: SensitiveDataType
        let positive: String
        let negative: String
        let fixtureID: String?

        init(
            type: SensitiveDataType,
            positive: String,
            negative: String,
            fixtureID: String? = nil
        ) {
            self.type = type
            self.positive = positive
            self.negative = negative
            self.fixtureID = fixtureID
        }
    }

    // WO-141@v3: each checkout provider grammar has an offline positive and boundary fixture.
    // WO-484: fixtures are synthetic and offline; none are usable credentials.
    private var fixtures: [Fixture] {
        [
            .init(type: .awsKey, positive: "AKIA" + String(repeating: "A", count: 16), negative: "AKIA" + String(repeating: "A", count: 15)),
            // WO-487: each sourced genericApiKey grammar has its own boundary fixture.
            .init(type: .genericApiKey, positive: "ghp_" + String(repeating: "B", count: 36), negative: "ghp_" + String(repeating: "B", count: 35), fixtureID: "github-classic-token"),
            .init(type: .genericApiKey, positive: "sk_live_" + String(repeating: "C", count: 24), negative: "sk_live_" + String(repeating: "C", count: 23), fixtureID: "stripe-api-key"),
            .init(type: .genericApiKey, positive: "whsec_" + String(repeating: "D", count: 24), negative: "whsec_" + String(repeating: "D", count: 23), fixtureID: "stripe-webhook-secret"),
            // WO-141@v3: checkout session possession tokens have independent boundary coverage.
            .init(type: .genericApiKey, positive: ["cs_", "live_", String(repeating: "E", count: 24)].joined(), negative: ["cs_", "live_", String(repeating: "E", count: 23)].joined(), fixtureID: "stripe-checkout-session"),
            .init(type: .slackWebhook, positive: "https://hooks.slack.com/services/TABC/BDEF/Token123", negative: "https://hooks.slack.com/services/ABC/BDEF/Token123"),
            .init(type: .discordWebhook, positive: "https://discord.com/api/webhooks/123456/Token_123", negative: "https://discord.com/api/webhooks/id/Token_123"),
            .init(type: .openaiKey, positive: "sk-proj-" + String(repeating: "C", count: 20), negative: "sk-proj-" + String(repeating: "C", count: 19)),
            .init(type: .anthropicKey, positive: "sk-ant-api03-" + String(repeating: "D", count: 20), negative: "sk-ant-api03-" + String(repeating: "D", count: 19)),
            // WO-145: Alibaba's generated Model Studio SDK documents a dot-separated sk-ws key.
            .init(
                type: .dashscopeKey,
                positive: "sk-ws-abc." + String(repeating: "D", count: 20),
                negative: "sk-ws-abc." + String(repeating: "D", count: 19)
            ),
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

    // WO-141@v3: checkout provenance extends the explicit family inventory without changing its types.
    // WO-145: keep DashScope in the explicit provider inventory and evidence manifest.
    func testManifestCoversExplicitProviderDetectorSet() {
        // WO-145: both detector fixtures and source evidence enumerate DashScope.
        let expected: Set<SensitiveDataType> = [
            .awsKey, .genericApiKey, .slackWebhook, .discordWebhook, .openaiKey,
            .anthropicKey, .dashscopeKey, .huggingfaceToken, .groqKey, .npmToken, .pypiToken,
            .rubygemsToken, .gitlabToken, .telegramBotToken, .sendgridKey,
            .shopifyToken, .digitaloceanToken, .perplexityKey, .workledgerKey,
            .oraculKey, .obstalabsKey, .resendKey, .vaultToken, .slackToken,
            .googleApiKey, .dockerAccessToken, .githubToken,
        ]
        let manifest = DetectionRules.providerTokenPatternManifest

        XCTAssertEqual(Set(manifest.map(\.type)), expected)
        XCTAssertEqual(Set(fixtures.map(\.type)), expected)
        // WO-141@v3: four generic provider families share one detector type.
        XCTAssertEqual(manifest.count, expected.count + 3)
        // WO-141@v3: the fixture inventory mirrors every sourced provider family.
        XCTAssertEqual(fixtures.count, expected.count + 3)
        XCTAssertEqual(Set(manifest.map(\.fixtureID)).count, manifest.count)
        XCTAssertEqual(
            Set(manifest.filter { $0.type == .genericApiKey }.map(\.fixtureID)),
            // WO-141@v3: checkout sessions join the closed generic provider inventory.
            ["github-classic-token", "stripe-api-key", "stripe-webhook-secret", "stripe-checkout-session"]
        )
        XCTAssertEqual(
            Set(fixtures.compactMap(\.fixtureID)),
            Set(manifest.filter { $0.type == .genericApiKey }.map(\.fixtureID))
        )
        XCTAssertFalse(manifest.contains { $0.provider == "Prefixed tokens" })
        XCTAssertTrue(manifest.allSatisfy { $0.primarySource.hasPrefix("https://") })
        XCTAssertEqual(manifest.first { $0.type == .dashscopeKey }?.reviewedOn, "2026-07-17")
        // WO-141@v3: the newly reviewed family has its own date without changing older provenance.
        XCTAssertEqual(manifest.first { $0.fixtureID == "stripe-checkout-session" }?.reviewedOn, "2026-10-04")
        // WO-141@v3: retain the historical review-date assertion for every unchanged family.
        XCTAssertTrue(manifest.filter {
            $0.type != .dashscopeKey && $0.fixtureID != "stripe-checkout-session"
        }.allSatisfy { $0.reviewedOn == "2026-07-15" })
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
