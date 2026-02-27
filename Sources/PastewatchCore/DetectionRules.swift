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
        // 40 character base64-ish string (often near AKIA keys)
        if let regex = try? NSRegularExpression(
            pattern: #"\b[A-Za-z0-9/+=]{40}\b"#,
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

        // Credential key=value pairs - high confidence
        // Matches password=, secret:, api_key=, etc.
        // Placed after API key patterns so specific tokens match first.
        // Ported from chainwatch internal/redact/scanner.go
        if let regex = try? NSRegularExpression(
            pattern: #"(?i)(?:password|passwd|secret|token|api_key|apikey|auth|credentials?)[ \t]*[=:][ \t]*\S+"#,
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

        return matches
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
                    type: .credential,
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
        case .ipAddress:  return isValidIP(value)
        case .phone:      return isValidPhone(value)
        case .creditCard: return isValidLuhn(value)
        case .email:      return isValidEmail(value)
        case .hostname:   return isValidHostname(value, config: config)
        case .filePath:   return isValidFilePath(value)
        case .uuid:       return isValidUUID(value)
        default:          return true
        }
    }

    private static func isValidIP(_ value: String) -> Bool {
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
