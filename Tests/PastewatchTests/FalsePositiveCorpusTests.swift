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
        "config-keys-benign-values": [
            "timeout: 3600", "retries: 3", "enabled: true", "level: debug",
            "port: 8443", "workers: 4", "mode: strict",
        ],
    ]

    // WO-569: benign corpus must not produce guard-blocking findings.
    func testBenignCorpusProducesNoGuardBlockingFindings() {
        for (klass, lines) in Self.benignCorpus {
            for line in lines {
                let matches = DetectionRules.scan(line, config: config)
                let blocking = matches.filter { $0.effectiveSeverity >= .high }
                XCTAssertTrue(
                    blocking.isEmpty,
                    "[\(klass)] benign line must not produce a guard-blocking (>= high) finding: "
                        + "\(line) -> \(blocking.map { "\($0.type)/\($0.effectiveSeverity)" })"
                )
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
