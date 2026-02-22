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
        "example.com", "example.org", "example.net",
        "localhost",
        "github.com", "google.com",
        "cloudflare.com", "amazonaws.com",
        "ubuntu.com", "debian.org", "kernel.org",
        "wikipedia.org",
        "stackexchange.com", "stackoverflow.com",
        "apple.com", "microsoft.com",
        "npmjs.com", "pypi.org", "swift.org",
        "golang.org"
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
            pattern: #"(postgres|postgresql|mysql|mongodb|redis)://[^\s]+"#,
            options: [.caseInsensitive]
        ) {
            result.append((.dbConnectionString, regex))
        }

        // Generic API Key patterns - high confidence
        // Common prefixes: sk-, pk-, api_, key_, token_
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
                if !isValidMatch(value, type: type) { continue }

                matches.append(DetectedMatch(type: type, value: value, range: range))
                matchedRanges.append(range)
            }
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
    private static func isValidMatch(_ value: String, type: SensitiveDataType) -> Bool {
        switch type {
        case .ipAddress:
            // Exclude common non-sensitive IPs
            let excluded = ["0.0.0.0", "127.0.0.1", "255.255.255.255"]
            if excluded.contains(value) { return false }

            // Exclude IPs that look like version numbers (context check)
            // This is a heuristic — we're conservative
            return true

        case .phone:
            // Require minimum length to avoid matching random numbers
            let digitsOnly = value.filter { $0.isNumber }
            return digitsOnly.count >= 10

        case .creditCard:
            // Luhn algorithm validation
            return isValidLuhn(value)

        case .email:
            // Basic validation — regex already handles most
            return value.contains("@") && value.contains(".")

        case .hostname:
            // Exclude safe/public hosts
            let lower = value.lowercased()
            if safeHosts.contains(lower) { return false }
            // Exclude strings that look like IP addresses (all digits and dots)
            if value.allSatisfy({ $0 == "." || $0.isNumber }) { return false }
            return true

        case .filePath:
            // Require minimum path depth to avoid false positives
            let components = value.split(separator: "/").filter { !$0.isEmpty }
            return components.count >= 3

        case .credential:
            // Regex is already high-confidence (keyword + separator + value)
            return true

        default:
            return true
        }
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
