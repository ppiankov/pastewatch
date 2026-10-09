import XCTest
@testable import PastewatchCore

/// WO-569: standing false-positive golden corpus + true-positive guard.
///
/// The benign corpus is a checked-in set of realistic NON-secret lines drawn from real
/// code, config, and docs. None is a secret. The test asserts the corpus produces zero
/// findings at or above the guard threshold (`.high`) under the default config — the code
/// path that actually blocks a user via the PreToolUse guard hook. This makes a precision
/// regression fail the build instead of surfacing when an operator hits it in production.
///
/// The companion true-positive guard proves the corpus gate did not blind the detector:
/// real-shaped secrets MUST still fire, so tightening precision can never be gamed by
/// weakening detection.
///
/// Corpus policy: any benign line that trips a finding at/above `.high` is a real FP and
/// must be fixed (a focused detector WO) — never silently removed from the corpus.
/// Ambiguous, opt-in-off classes (File Path / Hostname / Email at medium, per WO-529) are
/// intentionally out of the block-clean assertion: they do not fire by default and do not
/// block the guard.
final class FalsePositiveCorpusTests: XCTestCase {
    private let config = PastewatchConfig.defaultConfig

    /// Benign lines grouped by false-positive class. Every line is NON-secret.
    private static let benignCorpus: [String: [String]] = [
        "crypto-algorithm-names": [
            "auth: Ed25519", "alg: RS256", "signature: ES256", "hash: SHA256",
            "cipher: AES256-GCM", "kex: X25519", "curve: secp256k1", "kdf: argon2id",
            "jwt alg: HS512", "digest: BLAKE2b", "mac: HMAC",
        ],
        "auth-config-vocabulary": [
            "auth: none", "auth: required", "auth: oauth2", "auth: mtls", "auth: basic",
            "token type: Bearer", "grant type: client_credentials", "scope: read write",
            "flow: authorization_code", "audience: api", "issuer: accounts",
        ],
        "code-identifiers-go": [
            "resp.Body.Close()", "node.HostStartedAt.IsZero()", "r.Wo.ID",
            "ask.Envelope.Delivery", "p.CreatedAt.Format(time.RFC3339)",
            "cfg.Auth.Enabled", "client.Token.Refresh()", "req.Header.Get",
        ],
        "code-identifiers-lowercase": [
            "opt = parse()", "arg_small_p95 = args.small_p95_slo_seconds",
            "token = arg_small_p95", "secret = computedValue",
            "api_key = options.apiKey", "credentials := requestCredentials()",
        ],
        "ecosystem-hosts": [
            "host: proxy.golang.org", "url: google.golang.org/grpc",
            "endpoint: .fly.dev", "registry: registry.npmjs.org", "mirror: pypi.org",
            "cdn: cdn.jsdelivr.net", "repo: github.com/owner/name",
        ],
        "public-emails": [
            "contact: hello@example.com", "support: noreply@github.com",
            "maintainer: team@openssl.org",
        ],
        "prose-with-secret-words": [
            "The password policy requires rotation every 90 days.",
            "Store your API key in an environment variable, never in code.",
            "This token expires after one hour.",
            "The secret manager holds all credentials.",
            "Rotate the access key if it leaks.",
        ],
        "package-registry-names": [
            "dependency: token-bucket", "package: jsonwebtoken", "module: crypto",
            "lib: secretbox", "crate: ring", "gem: bcrypt",
        ],
        // WO-571@v2: canonical digit runs / cutsets are not phone numbers.
        "digit-runs-and-cutsets": [
            "strings.TrimRight(key, \"0123456789\")",
            "const digits = \"0123456789\"",
            "charset := \"0123456789\"",
            "re.compile(r\"[0123456789]+\")",
            "id: 1234567890",
            "00000000-0000-0000-0000-000000000000",
        ],
        // WO-667@v1: curl timing output is decimal data, not a telephone number.
        "decimal-phone-timings": [
            "http=200 t=245.014848", "time_total=12.345678", "latency=0.004512",
            "245.014848", "0.123456789", "1234.5",
            "t=8123.456789", "time_total=0.81234567890", "latency=001.234567890",
            "curl -w 'http=%{http_code} t=%{time_total}' output: http=200 t=8123.456789"
        ],
        "config-keys-benign-values": [
            "timeout: 3600", "retries: 3", "enabled: true", "level: debug",
            "port: 8443", "workers: 4", "mode: strict",
        ],
        // WO-661@v2: synthetic oracul identifier rows pin the canonical UUID/Phone false-positive class.
        "uuid-phone-slices": [
            "OptionID: \"" + ["1844" + "0000", "0000", "4000", "8000", "00000000" + "0005"].joined(separator: "-") + "\",",
            "{\"assumption_id\": \"" + ["1844" + "0000", "0000", "4000", "8000", "00000000" + "0006"].joined(separator: "-") + "\"}",
            "assumption_id: \"" + ["1844" + "0000", "0000", "4000", "8000", "00000000" + "0006"].joined(separator: "-") + "\""
        ],
        // WO-633: assemble documentation shapes without embedding scanner-triggering literals in source.
        "bare-dsn-prose": [
            ["- Detects connection strings (`", "post", "gres", "://", "`, `", "mongo", "db", "://", "`)."].joined(),
            ["- ClickHouse connection string detection (`", "click", "house", "://", "`)."].joined(),
            "- Plain prose about databases and credentials, no examples.",
        ],
        // WO-633: markdown closing delimiters must not turn boolean/null literals into credentials.
        "credential-literal-prose": ["true", "false", "null", "\"true\""].map {
            "- Credential regex: exclude literal values (`" + ["pass", "word", "="].joined() + $0 + "`)."
        },
    // WO-668@v1: the golden corpus includes the focused language fixtures without duplicating them.
    ].merging(CredentialCodeExpressionFixtures.rowsByLanguage) { existing, _ in existing }

    // WO-668@v1: enabling Credential makes code-expression false positives measurable, not hidden by defaults.
    func testCodeExpressionCorpusAndCredentialControls() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let enabled = TestConfigHelper.configWithAmbiguousAdvisories([.credential])
            let falsePositives = Self.benignCorpus.values.flatMap { $0 }.reduce(0) { count, row in
                count + DetectionRules.scan(row, config: enabled).filter { $0.effectiveSeverity >= .high }.count
            }
            var falseNegatives = 0
            // WO-668@v1: accepted reference-shaped misses are named, not hidden from the corpus count.
            let controls = CredentialCodeExpressionFixtures.literalControls + CredentialCodeExpressionFixtures.documentedFalseNegatives
            for control in controls
            where try control.matches(config: enabled).isEmpty {
                falseNegatives += 1
            }
            print("WO-668 corpus FP=\(falsePositives) FN=\(falseNegatives)")
            XCTAssertEqual(falsePositives, 0, "Corpus high-severity false-positive count")
            // WO-668@v1: only the pinned reference/default misses remain after constructor coverage is restored.
            XCTAssertEqual(falseNegatives, CredentialCodeExpressionFixtures.documentedFalseNegatives.count,
                           "Credential literal control false-negative count")
            XCTAssertEqual(CredentialCodeExpressionFixtures.rowsByLanguage.count, 7)
            for rows in CredentialCodeExpressionFixtures.rowsByLanguage.values {
                XCTAssertGreaterThanOrEqual(rows.count, 2)
            }
        }
    }

    // WO-667@v1: report corpus precision with Phone enabled so default-off cannot conceal a false positive.
    func testDecimalCorpusAndPhoneControls() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let enabled = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            var falsePositives = 0
            for lines in Self.benignCorpus.values {
                for row in lines {
                    falsePositives += DetectionRules.scan(row, config: enabled)
                        .filter { $0.effectiveSeverity >= .high }.count
                }
            }
            let controls: [String] = [
                ["+1", "415", "555", "0132"].joined(separator: " "),
                ["(", "415", ") ", "555", "-0132"].joined(),
                ["+65", "6123", "4567"].joined(separator: " "),
                ["+1", "415", "555", "0132"].joined(separator: ".")
            ]
            let falseNegatives = controls.filter {
                !DetectionRules.scan($0, config: enabled).contains { $0.type == .phone }
            }.count
            print("WO-667 corpus FP=\(falsePositives) FN=\(falseNegatives)")
            XCTAssertEqual(falsePositives, 0, "Corpus high-severity false-positive count")
            XCTAssertEqual(falseNegatives, 0, "Phone control false-negative count")
            for row in try XCTUnwrap(Self.benignCorpus["decimal-phone-timings"]) {
                XCTAssertFalse(DetectionRules.scan(row, config: config).contains { $0.type == .phone })
                for control in controls.prefix(3) {
                    let phones = DetectionRules.scan(row + " contact=" + control, config: enabled)
                        .filter { $0.type == .phone }
                    XCTAssertEqual(phones.count, 1, "Phone count beside a decimal token")
                }
            }
        }
    }

    // WO-661@v2: default-off Phone must not mask a golden-corpus precision regression.
    func testUUIDCorpusWithPhoneEnabledProducesNoPhoneFindings() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let enabled = TestConfigHelper.configWithAmbiguousAdvisories([.phone])
            XCTAssertTrue(enabled.isTypeEnabled(.phone))
            for (index, row) in try XCTUnwrap(Self.benignCorpus["uuid-phone-slices"]).enumerated() {
                let phones = DetectionRules.scan(row, config: enabled).filter { $0.type == .phone }
                XCTAssertTrue(phones.isEmpty, "Phone line \(index + 1) count=\(phones.count)")
            }
        }
    }

    // WO-569: benign corpus must not produce guard-blocking findings.
    func testBenignCorpusProducesNoGuardBlockingFindings() {
        for (klass, lines) in Self.benignCorpus {
            // WO-633: failure diagnostics identify corpus rows, never matched values.
            for (index, line) in lines.enumerated() {
                let matches = DetectionRules.scan(line, config: config)
                let blocking = matches.filter { $0.effectiveSeverity >= .high }
                XCTAssertTrue(
                    blocking.isEmpty,
                    // WO-633: retain type/severity evidence without exposing fixture content.
                    "[\(klass)] line \(index + 1): \(blocking.count) guard-blocking findings "
                        + "\(blocking.map { "\($0.type)/\($0.effectiveSeverity)" })"
                )
            }
        }
    }

    // WO-633: default-off alone must not mask precision regressions when these detectors are enabled.
    func testDocumentationCorpusWithEnabledDetectors() throws {
        var enabledConfig = config
        enabledConfig.enabledTypes += [SensitiveDataType.dbConnectionString.rawValue, SensitiveDataType.credential.rawValue]
        for klass in ["bare-dsn-prose", "credential-literal-prose"] {
            let lines = try XCTUnwrap(Self.benignCorpus[klass])
            for (index, line) in lines.enumerated() {
                let blocking = DetectionRules.scan(line, config: enabledConfig).filter { $0.effectiveSeverity >= .high }
                XCTAssertTrue(blocking.isEmpty, "[\(klass)] line \(index + 1): \(blocking.count) blocking findings")
            }
        }
    }

    // WO-569: corpus breadth guard.
    func testBenignCorpusHasMeaningfulSize() {
        let total = Self.benignCorpus.values.reduce(0) { $0 + $1.count }
        XCTAssertGreaterThanOrEqual(total, 60, "corpus should be broad enough to catch regressions")
    }

    // WO-569: true-positive guard — intrinsic detection must not be weakened.
    /// True-positive guard: real-shaped secrets MUST still fire. Values assembled from
    /// fragments so no literal secret sits in source; each is a realistic secret shape.
    func testTruePositivesStillFire() {
        // Intrinsic (always-on, tier-1) secrets must ALWAYS fire regardless of config.
        // These are the detections a precision fix must never weaken. Ambiguous/opt-in
        // classes (generic credential, DSN, email, host) are governed by WO-529 defaults
        // and are intentionally not asserted here.
        let awsKey = "AKIA" + "IOSFODNN7EXAMPLE"
        let anthropicKey = "sk-ant-api03-" + String(repeating: "A", count: 40)
        let intrinsicSecrets: [String] = [
            "AWS_ACCESS_KEY_ID=" + awsKey,
            "ANTHROPIC_API_KEY=" + anthropicKey,
        ]
        for secret in intrinsicSecrets {
            let matches = DetectionRules.scan(secret, config: config)
            XCTAssertFalse(
                matches.isEmpty,
                "intrinsic secret must still be detected (corpus gate must not blind the detector): \(secret)"
            )
        }
    }
}
