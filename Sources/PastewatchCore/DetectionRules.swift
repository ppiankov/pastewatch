import Foundation

/// Deterministic detection rules for sensitive data.
/// No ML. No confidence scores. No guessing.
///
/// Each rule is a regex pattern that matches high-confidence patterns only.
/// False negatives are preferred over false positives.
public struct DetectionRules {

    /// Safe hosts that should not trigger hostname detection.
    /// Matches chainwatch's safeHosts for consistency across tools.
    static let safeHosts: Set<String> = [
        // Common public domains
        "example.com", "example.org", "example.net",
        "localhost",
        "github.com", "google.com",
        "cloudflare.com", "amazonaws.com",
        "ubuntu.com", "debian.org", "kernel.org",
        "wikipedia.org",
        "stackexchange.com", "stackoverflow.com",
        "apple.com", "microsoft.com",
        "npmjs.com", "pypi.org", "swift.org",
        "golang.org",
        // Badge and CI services
        "img.shields.io", "badge.fury.io",
        "badgen.net", "codecov.io",
        "coveralls.io", "codeclimate.com",
        "sonarcloud.io", "snyk.io",
        // CI/CD platforms
        "travis-ci.org", "travis-ci.com",
        "circleci.com",
        // Package registries
        "crates.io", "rubygems.org",
        "pkg.go.dev", "registry.npmjs.org",
        "hub.docker.com", "ghcr.io",
        // Documentation and hosting
        "readthedocs.io", "readthedocs.org",
        "docs.aws.amazon.com", "cloud.google.com",
        "learn.microsoft.com",
        // Dev tools and platforms
        "gitlab.com", "bitbucket.org",
        "brew.sh", "docker.com",
        // CDN and static content
        "cdn.jsdelivr.net", "unpkg.com",
        "cdnjs.cloudflare.com",
        // Project-specific
        "raw.githubusercontent.com",
        "ancc.dev"
    ]

    /// All detection rules, ordered by specificity (most specific first).
    public static let rules: [(SensitiveDataType, NSRegularExpression)] = {
        var result: [(SensitiveDataType, NSRegularExpression)] = []

        // SSH Private Key - very high confidence
        // Matches the header of SSH private keys
        if let regex = try? NSRegularExpression(
            pattern: #"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----"#,
            options: []
        ) {
            result.append((.sshPrivateKey, regex))
        }

        // AWS Access Key ID - high confidence
        // Format: AKIA followed by 16 alphanumeric characters
        if let regex = try? NSRegularExpression(
            pattern: #"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"#,
            options: []
        ) {
            result.append((.awsKey, regex))
        }

        // AWS Secret Access Key - high confidence
        // 40 character base64-ish string preceded by AWS-related keyword
        // Requires context to avoid matching git SHAs, test function names, etc.
        if let regex = try? NSRegularExpression(
            pattern: #"(?i)(?:aws.?secret|secret.?access.?key|aws.?key)[ \t]*[=:]\s*[A-Za-z0-9/+=]{40}\b"#,
            options: []
        ) {
            result.append((.awsKey, regex))
        }

        // JWT Token - high confidence
        // Three base64url segments separated by dots
        if let regex = try? NSRegularExpression(
            pattern: #"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"#,
            options: []
        ) {
            result.append((.jwtToken, regex))
        }

        // Database Connection String - high confidence
        // PostgreSQL, MySQL, MongoDB connection strings
        if let regex = try? NSRegularExpression(
            pattern: #"(postgres|postgresql|mysql|mongodb|redis|clickhouse)://[^\s]+"#,
            options: [.caseInsensitive]
        ) {
            result.append((.dbConnectionString, regex))
        }

        // Slack Webhook URL - high confidence
        if let regex = try? NSRegularExpression(
            pattern: #"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"#,
            options: []
        ) {
            result.append((.slackWebhook, regex))
        }

        // Discord Webhook URL - high confidence
        if let regex = try? NSRegularExpression(
            pattern: #"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"#,
            options: []
        ) {
            result.append((.discordWebhook, regex))
        }

        // Azure Storage Connection String - high confidence
        if let regex = try? NSRegularExpression(
            pattern: #"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"#,
            options: []
        ) {
            result.append((.azureConnectionString, regex))
        }

        // GCP Service Account JSON - high confidence
        if let regex = try? NSRegularExpression(
            pattern: #""type"\s*:\s*"service_account""#,
            options: []
        ) {
            result.append((.gcpServiceAccount, regex))
        }

        // OpenAI API Key - high confidence
        // sk-proj- (project keys), sk-svcacct- (service account keys)
        if let regex = try? NSRegularExpression(
            pattern: #"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b"#,
            options: []
        ) {
            result.append((.openaiKey, regex))
        }

        // Anthropic API Key - high confidence
        // sk-ant-api03-, sk-ant-admin01-, sk-ant-oat01-
        if let regex = try? NSRegularExpression(
            pattern: #"\bsk-ant-(?:api03|admin01|oat01)-[A-Za-z0-9_-]{20,}\b"#,
            options: []
        ) {
            result.append((.anthropicKey, regex))
        }

        // Groq API Key - high confidence
        // gsk_ prefix
        if let regex = try? NSRegularExpression(
            pattern: #"\bgsk_[A-Za-z0-9]{20,}\b"#,
            options: []
        ) {
            result.append((.groqKey, regex))
        }

        // Hugging Face Token - high confidence
        // hf_ prefix
        if let regex = try? NSRegularExpression(
            pattern: #"\bhf_[A-Za-z0-9]{20,}\b"#,
            options: []
        ) {
            result.append((.huggingfaceToken, regex))
        }

        // npm Token - high confidence
        // npm_ prefix
        if let regex = try? NSRegularExpression(
            pattern: #"\bnpm_[A-Za-z0-9]{20,}\b"#,
            options: []
        ) {
            result.append((.npmToken, regex))
        }

        // PyPI Token - high confidence
        // pypi- prefix
        if let regex = try? NSRegularExpression(
            pattern: #"\bpypi-[A-Za-z0-9_-]{20,}\b"#,
            options: []
        ) {
            result.append((.pypiToken, regex))
        }

        // RubyGems Token - high confidence
        // rubygems_ prefix
        if let regex = try? NSRegularExpression(
            pattern: #"\brubygems_[A-Za-z0-9]{20,}\b"#,
            options: []
        ) {
            result.append((.rubygemsToken, regex))
        }

        // GitLab Personal Access Token - high confidence
        // glpat- prefix
        if let regex = try? NSRegularExpression(
            pattern: #"\bglpat-[A-Za-z0-9_-]{20,}\b"#,
            options: []
        ) {
            result.append((.gitlabToken, regex))
        }

        // Telegram Bot Token - high confidence
        // Numeric bot ID (8-10 digits) : AA followed by 33 chars
        if let regex = try? NSRegularExpression(
            pattern: #"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b"#,
            options: []
        ) {
            result.append((.telegramBotToken, regex))
        }

        // SendGrid API Key - high confidence
        // SG. followed by two base64 segments separated by a dot
        if let regex = try? NSRegularExpression(
            pattern: #"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"#,
            options: []
        ) {
            result.append((.sendgridKey, regex))
        }

        // Shopify Token - high confidence
        // shpat_, shpca_, shppa_ prefixes
        if let regex = try? NSRegularExpression(
            pattern: #"\bshp(?:at|ca|pa)_[A-Fa-f0-9]{20,}\b"#,
            options: []
        ) {
            result.append((.shopifyToken, regex))
        }

        // DigitalOcean Token - high confidence
        // dop_v1_ (personal), doo_v1_ (OAuth)
        if let regex = try? NSRegularExpression(
            pattern: #"\bdo[op]_v1_[a-f0-9]{64}\b"#,
            options: []
        ) {
            result.append((.digitaloceanToken, regex))
        }

        // Workledger API Key - high confidence
        // wl_sk_ prefix followed by 32+ base64url characters
        if let regex = try? NSRegularExpression(
            pattern: #"\bwl_sk_[A-Za-z0-9_-]{32,}\b"#,
            options: []
        ) {
            result.append((.workledgerKey, regex))
        }

        // Oracul API Key - high confidence
        // vc_<role>_ prefix followed by 32 hex characters
        if let regex = try? NSRegularExpression(
            pattern: #"\bvc_(?:admin|beta|pro|enterprise)_[0-9a-f]{32}\b"#,
            options: []
        ) {
            result.append((.oraculKey, regex))
        }

        // ObstaLabs License Key - high confidence
        // ol_ prefix + base64url payload + literal dot + base64url Ed25519 signature
        if let regex = try? NSRegularExpression(
            pattern: #"\bol_[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}"#,
            options: []
        ) {
            result.append((.obstalabsKey, regex))
        }

        // Resend API Key - high confidence
        // re_ prefix followed by 24+ alphanumeric characters
        if let regex = try? NSRegularExpression(
            pattern: #"\bre_[A-Za-z0-9]{24,}\b"#,
            options: []
        ) {
            result.append((.resendKey, regex))
        }

        // Perplexity API Key - high confidence
        // pplx- prefix followed by 48 alphanumeric characters
        if let regex = try? NSRegularExpression(
            pattern: #"\bpplx-[a-zA-Z0-9]{48}\b"#,
            options: []
        ) {
            result.append((.perplexityKey, regex))
        }

        // JDBC Connection URL - high confidence
        // Covers Oracle (thin/oci), PostgreSQL, MySQL, DB2, SQL Server, AS/400
        if let regex = try? NSRegularExpression(
            pattern: #"jdbc:[a-zA-Z0-9]+(?::[a-zA-Z0-9]+)*(?:://|:@|:@//)[^\s\"'<>]{5,}"#,
            options: []
        ) {
            result.append((.jdbcUrl, regex))
        }

        // XML Credential tags - high confidence
        // Catches <password>, <password_sha256_hex>, <secret_access_key>, etc.
        if let regex = try? NSRegularExpression(
            pattern: #"<(password[^>]*|secret[^>]*|token[^>]*|access_key[^>]*|secret_access_key)>([^<]+)</\1>"#,
            options: [.caseInsensitive]
        ) {
            result.append((.xmlCredential, regex))
        }

        // XML Username tags - high confidence
        // <user> within config context, <quota_key>
        if let regex = try? NSRegularExpression(
            pattern: #"<(user|quota_key)>([^<]+)</\1>"#,
            options: [.caseInsensitive]
        ) {
            result.append((.xmlUsername, regex))
        }

        // XML Hostname tags - high confidence
        // <host>, <hostname>, <interserver_http_host>
        if let regex = try? NSRegularExpression(
            pattern: #"<(host|hostname|interserver_http_host)>([^<]+)</\1>"#,
            options: [.caseInsensitive]
        ) {
            result.append((.xmlHostname, regex))
        }

        // Generic API Key patterns - high confidence
        // Common prefixes: sk-, pk-, api_, key_, token_
        // Placed AFTER specific providers (OpenAI sk-proj-, Anthropic sk-ant-, Groq gsk_)
        if let regex = try? NSRegularExpression(
            pattern: #"\b(sk|pk|api|key|token|secret|bearer)[_-][A-Za-z0-9]{20,}\b"#,
            options: [.caseInsensitive]
        ) {
            result.append((.genericApiKey, regex))
        }

        // GitHub Token - high confidence
        if let regex = try? NSRegularExpression(
            pattern: #"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"#,
            options: []
        ) {
            result.append((.genericApiKey, regex))
        }

        // Stripe API Key - high confidence
        if let regex = try? NSRegularExpression(
            pattern: #"\b(sk|pk|rk)_(test|live)_[A-Za-z0-9]{24,}\b"#,
            options: []
        ) {
            result.append((.genericApiKey, regex))
        }

        // Stripe Webhook Secret - high confidence
        // whsec_ prefix not covered by the generic sk/pk/api/key/token catch-all
        if let regex = try? NSRegularExpression(
            pattern: #"\bwhsec_[A-Za-z0-9]{24,}\b"#,
            options: []
        ) {
            result.append((.genericApiKey, regex))
        }

        // Credential key=value pairs - high confidence
        // Matches password=, secret:, api_key=, etc.
        // Placed after API key patterns so specific tokens match first.
        // Ported from chainwatch internal/redact/scanner.go
        // Excludes: boolean/trivial values (true, false, nil, etc.),
        //   env-lookup patterns (os.Getenv, process.env, ENV[), Go := declarations
        if let regex = try? NSRegularExpression(
            pattern: #"(?i)(?:password|passwd|secret|token|api_key|apikey|auth|credentials?)[ \t]*(?::=|[=:])[ \t]*(?!(?:true|false|yes|no|none|null|nil|0|1)(?:\s|$|[,;)\]}]))(?!os\.(?:Getenv|environ)|process\.env|ENV\[|ProcessInfo)\S{3,}"#,
            options: []
        ) {
            result.append((.credential, regex))
        }

        // File paths revealing infrastructure - high confidence
        // Matches /home/..., /var/..., /etc/..., etc.
        // Ported from chainwatch internal/redact/scanner.go
        if let regex = try? NSRegularExpression(
            pattern: #"(/(?:home|var|etc|root|usr|tmp|opt)/\S+)"#,
            options: []
        ) {
            result.append((.filePath, regex))
        }

        // UUID - high confidence
        // Standard UUID v4 format
        if let regex = try? NSRegularExpression(
            pattern: #"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#,
            options: [.caseInsensitive]
        ) {
            result.append((.uuid, regex))
        }

        // Credit Card - high confidence
        // Visa, Mastercard, Amex, Discover patterns with optional separators
        if let regex = try? NSRegularExpression(
            pattern: #"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"#,
            options: []
        ) {
            result.append((.creditCard, regex))
        }

        // IP Address - high confidence
        // IPv4 with valid octet ranges (not 0.0.0.0 or localhost)
        if let regex = try? NSRegularExpression(
            pattern: #"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#,
            options: []
        ) {
            result.append((.ipAddress, regex))
        }

        // Internal hostnames (FQDN) - with safe list filtering
        // Matches fully qualified domain names
        // Ported from chainwatch internal/redact/scanner.go
        if let regex = try? NSRegularExpression(
            pattern: #"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9]+\.[a-zA-Z]{2,}\b"#,
            options: []
        ) {
            result.append((.hostname, regex))
        }

        // Email Address - high confidence
        // Standard email format, excludes example.com
        if let regex = try? NSRegularExpression(
            pattern: #"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#,
            options: []
        ) {
            result.append((.email, regex))
        }

        // Phone Number - conservative, high confidence
        // International format: +XX XXXX XXXX XXXX (flexible spacing/separators)
        // Matches: Malaysian (+60), Indian (+91), Russian (+7), UK (+44), German (+49), etc.
        if let regex = try? NSRegularExpression(
            pattern: #"\+[1-9][0-9]{0,2}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{0,4}"#,
            options: []
        ) {
            result.append((.phone, regex))
        }

        // US format with area code in parentheses: (XXX) XXX-XXXX
        if let regex = try? NSRegularExpression(
            pattern: #"\([0-9]{3}\)\s?[0-9]{3}[-.\s]?[0-9]{4}"#,
            options: []
        ) {
            result.append((.phone, regex))
        }

        // Compact international without spaces (common in logs/configs)
        // E.164 format: +XXXXXXXXXXX (10-15 digits after +)
        if let regex = try? NSRegularExpression(
            pattern: #"\+[1-9][0-9]{9,14}\b"#,
            options: []
        ) {
            result.append((.phone, regex))
        }

        // Local formats without country code prefix
        // Malaysian local: 01X-XXXXXXX or 01XXXXXXXX (10-11 digits starting with 01)
        if let regex = try? NSRegularExpression(
            pattern: #"\b01[0-9][-.\s]?[0-9]{3,4}[-.\s]?[0-9]{4}\b"#,
            options: []
        ) {
            result.append((.phone, regex))
        }

        // Malaysian compact: 01XXXXXXXX (10-11 digits, no separators)
        if let regex = try? NSRegularExpression(
            pattern: #"\b01[0-9]{8,9}\b"#,
            options: []
        ) {
            result.append((.phone, regex))
        }

        // Russian local: 8XXXXXXXXXX (11 digits starting with 8)
        if let regex = try? NSRegularExpression(
            pattern: #"\b8[-.\s]?[0-9]{3}[-.\s]?[0-9]{3}[-.\s]?[0-9]{2}[-.\s]?[0-9]{2}\b"#,
            options: []
        ) {
            result.append((.phone, regex))
        }

        // Thai international dial: 00X-XXXXXXXXX (starts with 00)
        if let regex = try? NSRegularExpression(
            pattern: #"\b00[0-9]{1,3}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}\b"#,
            options: []
        ) {
            result.append((.phone, regex))
        }

        return result
    }()

    /// Patterns to exclude from detection (reduce false positives).
    /// Note: We intentionally do NOT exclude test/example domains for emails
    /// because in production, all emails should be detected.
    static let exclusionPatterns: [NSRegularExpression] = {
        var patterns: [NSRegularExpression] = []

        // Exclude localhost IP only (not general private ranges)
        if let regex = try? NSRegularExpression(
            pattern: #"^(127\.0\.0\.1|0\.0\.0\.0)$"#,
            options: []
        ) {
            patterns.append(regex)
        }

        return patterns
    }()

    /// Well-known test/example credentials that should never trigger detection.
    /// Values ending in EXAMPLE or containing test_ prefixes are fake by convention.
    static let testCredentials: Set<String> = [
        // AWS example key from docs (ends in EXAMPLE — AWS convention for fake keys)
        "AKIAIOSFODNN7EXAMPLE",
        // AWS example secret from docs
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        // Stripe test-mode keys (sk_test_ prefix = test mode, never real)
        "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
        "pk_test_TYooMQauvdEDq54NiTphI7jx",
    ]

    /// Check if a matched value is a known test credential.
    public static func isTestCredential(_ value: String) -> Bool {
        if testCredentials.contains(value) { return true }
        // AWS keys ending in EXAMPLE are always fake
        if value.hasPrefix("AKIA") && value.hasSuffix("EXAMPLE") { return true }
        // Stripe test-mode keys
        if value.hasPrefix("sk_test_") || value.hasPrefix("pk_test_") { return true }
        return false
    }

    /// Scan content for sensitive data.
    /// Returns all matches found.
    public static func scan(_ content: String, config: PastewatchConfig) -> [DetectedMatch] {
        var matches: [DetectedMatch] = []
        var matchedRanges: [Range<String.Index>] = []

        for (type, regex) in rules {
            // Skip disabled types
            guard config.isTypeEnabled(type) else { continue }

            let nsRange = NSRange(content.startIndex..., in: content)
            let regexMatches = regex.matches(in: content, options: [], range: nsRange)

            for match in regexMatches {
                guard let range = Range(match.range, in: content) else { continue }

                // Skip if this range overlaps with an already matched range
                let overlaps = matchedRanges.contains { existingRange in
                    range.overlaps(existingRange)
                }
                if overlaps { continue }

                let value = String(content[range])

                // Check exclusion patterns
                if shouldExclude(value) { continue }

                // Additional validation per type
                if !isValidMatch(value, type: type, config: config) { continue }

                let line = lineNumber(of: range.lowerBound, in: content)
                matches.append(DetectedMatch(type: type, value: value, range: range, line: line))
                matchedRanges.append(range)
            }
        }

        // Second pass: entropy-based detection (opt-in)
        if config.isTypeEnabled(.highEntropyString) {
            let tokens = tokenizeForEntropy(content)
            for (token, range) in tokens {
                guard token.count >= minimumEntropyLength else { continue }

                let overlaps = matchedRanges.contains { $0.overlaps(range) }
                if overlaps { continue }

                guard hasCharacterMix(token) else { continue }
                guard !isLikelyGitSHA(token) else { continue }
                guard shannonEntropy(token) >= entropyThreshold else { continue }

                let line = lineNumber(of: range.lowerBound, in: content)
                matches.append(DetectedMatch(type: .highEntropyString, value: token, range: range, line: line))
                matchedRanges.append(range)
            }
        }

        // Third pass: 2-segment hostnames for sensitiveHosts only
        // The main hostname regex requires 3+ segments (FQDN). This catches
        // 2-segment hosts like nas.local or printer.lan when they match a
        // sensitiveHosts entry.
        if config.isTypeEnabled(.hostname), !config.sensitiveHosts.isEmpty {
            scanTwoSegmentHosts(content, config: config, matches: &matches, matchedRanges: &matchedRanges)
        }

        return matches
    }

    /// WO-124: scan file IO using built-ins plus shared/generated pattern artifacts.
    public static func scanFileIO(_ content: String, config: PastewatchConfig) -> [DetectedMatch] {
        scanFileIOResult(content, config: config).matches
    }

    /// WO-126: scan file IO while preserving configured shared-pattern load diagnostics.
    public static func scanFileIOResult(_ content: String, config: PastewatchConfig) -> FileIOScanResult {
        let sharedRuleSet = SharedSecretPatternSource.fileIORuleSet(for: config)
        guard !sharedRuleSet.rules.isEmpty else {
            return FileIOScanResult(
                matches: scan(content, config: config),
                sharedPatternErrors: sharedRuleSet.errors
            )
        }
        return FileIOScanResult(
            matches: scan(content, config: config, customRules: sharedRuleSet.rules),
            sharedPatternErrors: sharedRuleSet.errors
        )
    }

    /// WO-126: file IO scan output with fail-closed diagnostics for callers that return content.
    public struct FileIOScanResult {
        public let matches: [DetectedMatch]
        public let sharedPatternErrors: [SharedSecretPatternLoadError]

        public var hasSharedPatternErrors: Bool {
            !sharedPatternErrors.isEmpty
        }
    }

    /// WO-126: fail closed on configured shared pattern load errors.
    public static func scanFileIOOrThrow(_ content: String, config: PastewatchConfig) throws -> [DetectedMatch] {
        let result = scanFileIOResult(content, config: config)
        guard !result.hasSharedPatternErrors else {
            throw SharedSecretPatternLoadError(
                path: "sharedPatternFiles",
                message: result.sharedPatternErrors.map(\.localizedDescription).joined(separator: "; ")
            )
        }
        guard !result.matches.isEmpty else {
            return scan(content, config: config)
        }
        return result.matches
    }

    /// Scan with allowlist filtering and custom rules.
    public static func scan(
        _ content: String,
        config: PastewatchConfig,
        allowlist: Allowlist = Allowlist(),
        customRules: [CustomRule] = []
    ) -> [DetectedMatch] {
        // Run built-in rules
        var matches = scan(content, config: config)
        var matchedRanges = matches.map { $0.range }

        // Run custom rules (after built-in, same overlap logic)
        for rule in customRules {
            let nsRange = NSRange(content.startIndex..., in: content)
            let regexMatches = rule.regex.matches(in: content, options: [], range: nsRange)

            for match in regexMatches {
                guard let range = Range(match.range, in: content) else { continue }

                let overlaps = matchedRanges.contains { $0.overlaps(range) }
                if overlaps { continue }

                let value = String(content[range])
                let line = lineNumber(of: range.lowerBound, in: content)
                matches.append(DetectedMatch(
                    type: rule.type,
                    value: value,
                    range: range,
                    line: line,
                    customRuleName: rule.name,
                    customSeverity: rule.severity
                ))
                matchedRanges.append(range)
            }
        }

        // Apply allowlist filtering
        if !allowlist.values.isEmpty || !allowlist.patterns.isEmpty {
            matches = allowlist.filter(matches)
        }

        return matches
    }

    /// Check if a value should be excluded from detection.
    private static func shouldExclude(_ value: String) -> Bool {
        for pattern in exclusionPatterns {
            let nsRange = NSRange(value.startIndex..., in: value)
            if pattern.firstMatch(in: value, options: [], range: nsRange) != nil {
                return true
            }
        }
        return false
    }

    /// Additional validation for specific types.
    private static func isValidMatch(_ value: String, type: SensitiveDataType, config: PastewatchConfig) -> Bool {
        switch type {
        case .ipAddress:   return isValidIP(value, config: config)
        case .phone:       return isValidPhone(value)
        case .creditCard:  return isValidLuhn(value)
        case .email:       return isValidEmail(value)
        case .hostname:    return isValidHostname(value, config: config)
        case .filePath:    return isValidFilePath(value)
        case .uuid:        return isValidUUID(value)
        case .credential:  return isValidCredential(value)
        default:           return true
        }
    }

    /// Validate credential key=value matches.
    /// Rejects common English words, documentation labels, and placeholders.
    private static func isValidCredential(_ fullMatch: String) -> Bool {
        // Extract just the value part (after = or :)
        guard let separatorRange = fullMatch.range(of: #"(?::=|[=:])\s*"#, options: .regularExpression) else {
            return true
        }
        let value = String(fullMatch[separatorRange.upperBound...])
            .trimmingCharacters(in: .whitespaces)

        return isValidCredentialValue(value)
    }

    /// Check if a key name (from JSON/YAML/properties) indicates a credential.
    /// Used by DirectoryScanner for key-aware detection in structured formats.
    public static func isCredentialKeyName(_ key: String) -> Bool {
        let lower = key.lowercased()
        let keywords = [
            "password", "passwd", "secret", "token", "api_key", "apikey",
            "auth_token", "access_key", "secret_key", "private_key",
            "credential", "dsn", "connection_string",
        ]
        return keywords.contains(where: { lower.contains($0) })
    }

    /// Validate a credential value in isolation (used by key-aware detection for JSON/YAML).
    public static func isValidCredentialValue(_ value: String) -> Bool {        // Too short to be a real secret
        if value.count < 4 { return false }

        // Skip env var references ($VAR, ${VAR}, %VAR%)
        if value.hasPrefix("$") || value.hasPrefix("%") { return false }

        // Skip common documentation/prose words after credential keywords
        let lowerValue = value.lowercased()
        let proseWords: Set<String> = [
            "rotated", "rotation", "required", "optional", "changed", "updated",
            "expired", "revoked", "generated", "managed", "stored", "provided",
            "configured", "enabled", "disabled", "deprecated", "removed",
            "encrypted", "hashed", "salted", "secured", "protected",
            "string", "value", "field", "method", "type", "format",
            "authentication", "authorization", "mechanism", "provider",
            "userpass", "kubernetes", "ldap", "oauth", "saml", "oidc",
            "file", "path", "directory", "location", "manager",
            "policy", "rule", "check", "validate", "verify",
            "outside", "inside", "above", "below", "here", "there",
            "please", "should", "would", "could", "must", "needs",
            "based", "using", "from", "with", "that", "this",
            "post", "get", "put", "delete", "patch", "head", "options",
            "https://", "http://", "ftp://",
        ]
        // Check first word of the value
        let firstWord = lowerValue.split(separator: " ").first.map(String.init) ?? lowerValue
        let cleanFirstWord = firstWord.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        if proseWords.contains(cleanFirstWord) { return false }

        // Skip URLs without auth (no user:pass@ segment)
        if (lowerValue.hasPrefix("https://") || lowerValue.hasPrefix("http://"))
            && !lowerValue.contains("@") { return false }

        // Require some complexity — pure lowercase alpha words are likely prose
        let hasDigit = value.contains(where: { $0.isNumber })
        let hasUpper = value.contains(where: { $0.isUppercase })
        let hasSpecial = value.contains(where: { "!@#$%^&*()_+-=[]{}|;:',.<>?/`~".contains($0) })
        let isAllLowerAlpha = value.allSatisfy { $0.isLowercase || $0 == "-" || $0 == "_" }

        // Pure lowercase word without digits or special chars is likely prose
        if isAllLowerAlpha && !hasDigit && !hasSpecial && value.count < 20 { return false }

        // At least two of: digits, uppercase, special chars → likely a real secret
        let complexityScore = (hasDigit ? 1 : 0) + (hasUpper ? 1 : 0) + (hasSpecial ? 1 : 0)
        if complexityScore == 0 && value.count < 20 { return false }

        return true
    }

    private static func isValidIP(_ value: String, config: PastewatchConfig) -> Bool {
        // sensitiveIPPrefixes override all exclusions (highest precedence)
        for prefix in config.sensitiveIPPrefixes where value.hasPrefix(prefix) {
            return true
        }

        let excluded: Set<String> = [
            "0.0.0.0", "127.0.0.1", "255.255.255.255",
            "8.8.8.8", "8.8.4.4",         // Google DNS
            "1.1.1.1", "1.0.0.1",         // Cloudflare DNS
            "9.9.9.9",                     // Quad9 DNS
            "208.67.222.222", "208.67.220.220", // OpenDNS
            "169.254.169.254",             // Cloud metadata endpoint
        ]
        if excluded.contains(value) { return false }

        // RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
        if value.hasPrefix("192.0.2.") || value.hasPrefix("198.51.100.") || value.hasPrefix("203.0.113.") {
            return false
        }

        // Multicast (224.x-239.x) and broadcast
        if let first = value.split(separator: ".").first, let octet = Int(first), octet >= 224 {
            return false
        }

        return true
    }

    private static func isValidPhone(_ value: String) -> Bool {
        let digitsOnly = value.filter { $0.isNumber }
        return digitsOnly.count >= 10
    }

    private static func isValidEmail(_ value: String) -> Bool {
        guard value.contains("@") && value.contains(".") else { return false }
        let lower = value.lowercased()
        let safeEmails: Set<String> = [
            "noreply@github.com", "no-reply@github.com",
            "dependabot[bot]@users.noreply.github.com",
            "actions@github.com", "github-actions[bot]@users.noreply.github.com",
            "noreply@example.com",
        ]
        if safeEmails.contains(lower) { return false }
        if lower.hasPrefix("noreply@") || lower.hasPrefix("no-reply@") { return false }
        if lower.hasSuffix("@users.noreply.github.com") { return false }
        return true
    }

    private static func isValidHostname(_ value: String, config: PastewatchConfig) -> Bool {
        let hostLower = value.lowercased()
        // sensitiveHosts always flag (highest precedence, exact + suffix)
        if hostMatches(hostLower, in: config.sensitiveHosts) { return true }
        // Built-in safe hosts (exact only) + user safe hosts (exact + suffix)
        if safeHosts.contains(hostLower) || hostMatches(hostLower, in: config.safeHosts) { return false }
        if value.allSatisfy({ $0 == "." || $0.isNumber }) { return false }
        return true
    }

    // Regex for 2-segment hostnames (e.g., nas.local, printer.lan).
    // swiftlint:disable:next force_try
    private static let twoSegmentHostRegex = try! NSRegularExpression(
        pattern: #"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b"#
    )

    /// Scan for 2-segment hostnames and flag only those matching sensitiveHosts.
    private static func scanTwoSegmentHosts(
        _ content: String,
        config: PastewatchConfig,
        matches: inout [DetectedMatch],
        matchedRanges: inout [Range<String.Index>]
    ) {
        let nsRange = NSRange(content.startIndex..., in: content)
        let regexMatches = twoSegmentHostRegex.matches(in: content, options: [], range: nsRange)

        for match in regexMatches {
            guard let range = Range(match.range, in: content) else { continue }
            let overlaps = matchedRanges.contains { $0.overlaps(range) }
            if overlaps { continue }

            let value = String(content[range])
            // Only flag if it matches a sensitiveHosts entry
            guard hostMatches(value.lowercased(), in: config.sensitiveHosts) else { continue }

            let line = lineNumber(of: range.lowerBound, in: content)
            matches.append(DetectedMatch(type: .hostname, value: value, range: range, line: line))
            matchedRanges.append(range)
        }
    }

    /// Check if a hostname matches any entry in a list (exact or suffix with leading dot).
    private static func hostMatches(_ host: String, in list: [String]) -> Bool {
        let hostLower = host.lowercased()
        for entry in list {
            let entryLower = entry.lowercased()
            if entryLower.hasPrefix(".") {
                if hostLower.hasSuffix(entryLower) { return true }
            } else {
                if hostLower == entryLower { return true }
            }
        }
        return false
    }

    private static func isValidFilePath(_ value: String) -> Bool {
        let components = value.split(separator: "/").filter { !$0.isEmpty }
        if components.count < 3 { return false }
        let safePaths: Set<String> = [
            "/dev/null", "/dev/zero", "/dev/stdin", "/dev/stdout", "/dev/stderr",
            "/dev/random", "/dev/urandom",
            "/bin/sh", "/bin/bash", "/bin/zsh",
            "/usr/bin/env", "/usr/bin/make", "/usr/bin/git",
            "/usr/local/bin", "/usr/local/lib",
            "/etc/hosts", "/etc/resolv.conf", "/etc/passwd",
            "/tmp", "/var/tmp",
        ]
        if safePaths.contains(value) { return false }
        if value.hasPrefix("/usr/bin/") || value.hasPrefix("/usr/lib/") { return false }
        return true
    }

    private static func isValidUUID(_ value: String) -> Bool {
        let nilUUIDs: Set<String> = [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ]
        return !nilUUIDs.contains(value.lowercased())
    }

    /// Compute 1-based line number for a string index.
    static func lineNumber(of index: String.Index, in content: String) -> Int {
        var line = 1
        var current = content.startIndex
        while current < index {
            if content[current] == "\n" {
                line += 1
            }
            current = content.index(after: current)
        }
        return line
    }

    // MARK: - Entropy detection

    private static let minimumEntropyLength = 20
    private static let entropyThreshold = 4.0

    /// Shannon entropy in bits per character.
    static func shannonEntropy(_ s: String) -> Double {
        guard !s.isEmpty else { return 0.0 }
        var freq: [Character: Int] = [:]
        for char in s { freq[char, default: 0] += 1 }
        let length = Double(s.count)
        var entropy = 0.0
        for count in freq.values {
            let p = Double(count) / length
            entropy -= p * (log(p) / log(2.0))
        }
        return entropy
    }

    /// Tokenize content for entropy scanning — split on delimiters.
    static func tokenizeForEntropy(_ content: String) -> [(token: String, range: Range<String.Index>)] {
        let delimiters = CharacterSet.whitespacesAndNewlines
            .union(CharacterSet(charactersIn: "\"'`=:;,(){}[]<>"))
        var results: [(String, Range<String.Index>)] = []
        var tokenStart: String.Index?

        for i in content.indices {
            let char = content[i]
            let isDelimiter = char.unicodeScalars.allSatisfy { delimiters.contains($0) }

            if isDelimiter {
                if let start = tokenStart {
                    let token = String(content[start..<i])
                    if !token.isEmpty {
                        results.append((token, start..<i))
                    }
                    tokenStart = nil
                }
            } else if tokenStart == nil {
                tokenStart = i
            }
        }

        // Handle last token
        if let start = tokenStart {
            let token = String(content[start..<content.endIndex])
            if !token.isEmpty {
                results.append((token, start..<content.endIndex))
            }
        }

        return results
    }

    /// Check if a string has at least 2 of: uppercase, lowercase, digits.
    private static func hasCharacterMix(_ s: String) -> Bool {
        var hasUpper = false
        var hasLower = false
        var hasDigit = false
        for char in s {
            if char.isUppercase {
                hasUpper = true
            } else if char.isLowercase {
                hasLower = true
            } else if char.isNumber {
                hasDigit = true
            }
        }
        let classes = [hasUpper, hasLower, hasDigit].filter { $0 }.count
        return classes >= 2
    }

    /// Check if a string looks like a git SHA (40 hex chars).
    private static func isLikelyGitSHA(_ s: String) -> Bool {
        guard s.count == 40 else { return false }
        return s.allSatisfy { $0.isHexDigit }
    }

    /// Luhn algorithm for credit card validation.
    private static func isValidLuhn(_ value: String) -> Bool {
        let digits = value.compactMap { $0.wholeNumberValue }
        guard digits.count >= 13 else { return false }

        var sum = 0
        for (index, digit) in digits.reversed().enumerated() {
            if index % 2 == 1 {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            } else {
                sum += digit
            }
        }
        return sum % 10 == 0
    }
}
