import Foundation

/// Deterministic detection rules for sensitive data.
/// No ML. No confidence scores. No guessing.
///
/// Rules provide deterministic detection. WO-487: mutation authorization is
/// separately attached only when a grammar proves provider-specific evidence.
public struct DetectionRules {
    private static let maximumPrivateKeyBlockCharacters = 262_144 // WO-478: bound malformed PEM scans.
    // WO-487: these sourced grammars authorize mutation independently of the
    // advisory-only genericApiKey type.
    private static let githubClassicTokenRegex = try? NSRegularExpression(
        pattern: #"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"#
    )
    private static let stripeAPIKeyRegex = try? NSRegularExpression(
        pattern: #"\b(sk|pk|rk)_(test|live)_[A-Za-z0-9]{24,}\b"#
    )
    private static let stripeWebhookSecretRegex = try? NSRegularExpression(
        pattern: #"\bwhsec_[A-Za-z0-9]{24,}\b"#
    )

    // WO-484: reviewed primary references travel with the intrinsic provider set.
    public static let providerTokenPatternManifest: [ProviderTokenPatternMetadata] = [
        .init(type: .awsKey, provider: "AWS", tokenFamily: "access keys", primarySource: "https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html", reviewedOn: "2026-07-15", fixtureID: "aws-access-key"),
        .init(type: .genericApiKey, provider: "GitHub", tokenFamily: "classic tokens", primarySource: "https://docs.github.com/authentication/keeping-your-account-and-data-secure/about-authentication-to-github", reviewedOn: "2026-07-15", fixtureID: "github-classic-token"),
        .init(type: .genericApiKey, provider: "Stripe", tokenFamily: "API keys", primarySource: "https://docs.stripe.com/keys", reviewedOn: "2026-07-15", fixtureID: "stripe-api-key"),
        .init(type: .genericApiKey, provider: "Stripe", tokenFamily: "webhook signing secrets", primarySource: "https://docs.stripe.com/webhooks/signature", reviewedOn: "2026-07-15", fixtureID: "stripe-webhook-secret"),
        .init(type: .slackWebhook, provider: "Slack", tokenFamily: "incoming webhook", primarySource: "https://api.slack.com/messaging/webhooks", reviewedOn: "2026-07-15", fixtureID: "slack-webhook"),
        .init(type: .discordWebhook, provider: "Discord", tokenFamily: "webhook", primarySource: "https://discord.com/developers/docs/resources/webhook", reviewedOn: "2026-07-15", fixtureID: "discord-webhook"),
        .init(type: .openaiKey, provider: "OpenAI", tokenFamily: "API key", primarySource: "https://platform.openai.com/docs/api-reference/authentication", reviewedOn: "2026-07-15", fixtureID: "openai-key"),
        .init(type: .anthropicKey, provider: "Anthropic", tokenFamily: "API key", primarySource: "https://docs.anthropic.com/en/api/getting-started", reviewedOn: "2026-07-15", fixtureID: "anthropic-key"),
        .init(
            type: .dashscopeKey,
            provider: "Alibaba Model Studio",
            tokenFamily: "workspace API key",
            primarySource: "https://github.com/aliyun/alibabacloud-typescript-sdk/blob/" +
                "c58a23fbbf7f0eac23cad75c01b6402104cef796/modelstudio-20260210/" +
                "src/models/CreateApiKeyResponseBody.ts",
            reviewedOn: "2026-07-17",
            fixtureID: "dashscope-workspace-key"
        ),
        .init(type: .huggingfaceToken, provider: "Hugging Face", tokenFamily: "user access token", primarySource: "https://huggingface.co/docs/hub/security-tokens", reviewedOn: "2026-07-15", fixtureID: "huggingface-token"),
        .init(type: .groqKey, provider: "Groq", tokenFamily: "API key", primarySource: "https://console.groq.com/docs/quickstart", reviewedOn: "2026-07-15", fixtureID: "groq-key"),
        .init(type: .npmToken, provider: "npm", tokenFamily: "access token", primarySource: "https://docs.npmjs.com/about-access-tokens", reviewedOn: "2026-07-15", fixtureID: "npm-token"),
        .init(type: .pypiToken, provider: "PyPI", tokenFamily: "API token", primarySource: "https://pypi.org/help/#apitoken", reviewedOn: "2026-07-15", fixtureID: "pypi-token"),
        .init(type: .rubygemsToken, provider: "RubyGems", tokenFamily: "API key", primarySource: "https://guides.rubygems.org/rubygems-org-api/", reviewedOn: "2026-07-15", fixtureID: "rubygems-token"),
        .init(type: .gitlabToken, provider: "GitLab", tokenFamily: "personal access token", primarySource: "https://docs.gitlab.com/user/profile/personal_access_tokens/", reviewedOn: "2026-07-15", fixtureID: "gitlab-token"),
        .init(type: .telegramBotToken, provider: "Telegram", tokenFamily: "bot token", primarySource: "https://core.telegram.org/bots/api", reviewedOn: "2026-07-15", fixtureID: "telegram-bot-token"),
        .init(type: .sendgridKey, provider: "SendGrid", tokenFamily: "API key", primarySource: "https://www.twilio.com/docs/sendgrid/api-reference/how-to-use-the-sendgrid-v3-api/authentication", reviewedOn: "2026-07-15", fixtureID: "sendgrid-key"),
        .init(type: .shopifyToken, provider: "Shopify", tokenFamily: "access token", primarySource: "https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens", reviewedOn: "2026-07-15", fixtureID: "shopify-token"),
        .init(type: .digitaloceanToken, provider: "DigitalOcean", tokenFamily: "personal and OAuth tokens", primarySource: "https://docs.digitalocean.com/reference/api/create-personal-access-token/", reviewedOn: "2026-07-15", fixtureID: "digitalocean-token"),
        .init(type: .perplexityKey, provider: "Perplexity", tokenFamily: "API key", primarySource: "https://docs.perplexity.ai/guides/getting-started", reviewedOn: "2026-07-15", fixtureID: "perplexity-key"),
        .init(type: .workledgerKey, provider: "Workledger", tokenFamily: "API key", primarySource: "https://github.com/ppiankov/workledger", reviewedOn: "2026-07-15", fixtureID: "workledger-key"),
        .init(type: .oraculKey, provider: "Oracul", tokenFamily: "API key", primarySource: "https://github.com/ppiankov/oracul", reviewedOn: "2026-07-15", fixtureID: "oracul-key"),
        .init(type: .obstalabsKey, provider: "ObstaLabs", tokenFamily: "license key", primarySource: "https://github.com/ppiankov/obstalabs", reviewedOn: "2026-07-15", fixtureID: "obstalabs-key"),
        .init(type: .resendKey, provider: "Resend", tokenFamily: "API key", primarySource: "https://resend.com/docs/dashboard/api-keys/introduction", reviewedOn: "2026-07-15", fixtureID: "resend-key"),
        .init(type: .vaultToken, provider: "HashiCorp Vault", tokenFamily: "service and batch tokens", primarySource: "https://developer.hashicorp.com/vault/docs/concepts/tokens", reviewedOn: "2026-07-15", fixtureID: "vault-token"),
        .init(type: .slackToken, provider: "Slack", tokenFamily: "bot, app, and rotating tokens", primarySource: "https://api.slack.com/authentication/token-types", reviewedOn: "2026-07-15", fixtureID: "slack-token"),
        .init(type: .googleApiKey, provider: "Google Cloud", tokenFamily: "API key", primarySource: "https://cloud.google.com/docs/authentication/api-keys", reviewedOn: "2026-07-15", fixtureID: "google-api-key"),
        .init(type: .dockerAccessToken, provider: "Docker", tokenFamily: "personal and organization access tokens", primarySource: "https://docs.docker.com/security/for-developers/access-tokens/", reviewedOn: "2026-07-15", fixtureID: "docker-access-token"),
        .init(type: .githubToken, provider: "GitHub", tokenFamily: "fine-grained and installation tokens", primarySource: "https://docs.github.com/authentication/keeping-your-account-and-data-secure/about-authentication-to-github", reviewedOn: "2026-07-15", fixtureID: "github-token"),
    ]

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
            // WO-480: contain the key value itself; do not consume adjacent JSON,
            // punctuation, or prose merely because no trailing semicolon exists.
            pattern: #"DefaultEndpointsProtocol=https;AccountName=[^;\s\"']+;AccountKey=[A-Za-z0-9+/=]+"#,
            options: []
        ) {
            result.append((.azureConnectionString, regex))
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

        // WO-145: the provider-published workspace key has a dot-separated payload.
        if let regex = try? NSRegularExpression(
            pattern: #"\bsk-ws-[A-Za-z0-9_-]{3,}\.[A-Za-z0-9._-]{20,}\b"#,
            options: []
        ) {
            result.append((.dashscopeKey, regex))
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

        // WO-462: https://developer.hashicorp.com/vault/docs/concepts/tokens
        // Reviewed 2026-07-15. Modern hv* tokens use 24+ URL-safe characters;
        // legacy one-letter tokens use exactly 24 base62 characters.
        if let regex = try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_.-])(?:hv[bsr]\.[A-Za-z0-9_-]{24,}|[sbr]\.[A-Za-z0-9]{24})(?![A-Za-z0-9_.-])"#
        ) {
            result.append((.vaultToken, regex))
        }

        // WO-481: https://docs.slack.dev/authentication/tokens/ and
        // https://api.slack.com/authentication/rotation, reviewed 2026-07-14.
        // Slack intentionally keeps token lengths variable, so prefix, separators,
        // bounded token characters, and a conservative suffix floor carry certainty.
        let slackPatterns = [
            #"(?<![A-Za-z0-9_.-])(?:xox[bp]|xapp|xwfp)-[A-Za-z0-9-]{20,255}(?![A-Za-z0-9_.-])"#,
            #"(?<![A-Za-z0-9_.-])xoxe\.xox[bp]-[0-9]+-[A-Za-z0-9-]{16,255}(?![A-Za-z0-9_.-])"#,
            #"(?<![A-Za-z0-9_.-])xoxe-[0-9]+-[A-Za-z0-9-]{16,255}(?![A-Za-z0-9_.-])"#
        ]
        for pattern in slackPatterns {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                result.append((.slackToken, regex))
            }
        }

        // WO-482: https://cloud.google.com/docs/authentication/api-keys
        // Reviewed 2026-07-14. Google's published example confirms AIza + 35 key characters.
        if let regex = try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"#
        ) {
            result.append((.googleApiKey, regex))
        }

        // WO-483: https://docs.docker.com/reference/api/ai-governance/
        // Reviewed 2026-07-15. Docker publishes PAT/OAT prefixes but not a fixed length;
        // its Hub API reference includes a valid 15-character PAT suffix.
        if let regex = try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_-])dckr_(?:pat|oat)_[A-Za-z0-9_-]{15,255}(?![A-Za-z0-9_-])"#
        ) {
            result.append((.dockerAccessToken, regex))
        }

        // WO-485: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github
        // Reviewed 2026-07-14. Fine-grained PAT lengths are variable; stateless
        // installation tokens use the documented ghs_APPID_JWT structure.
        if let regex = try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,255}(?![A-Za-z0-9_])"#
        ) {
            result.append((.githubToken, regex))
        }
        if let regex = try? NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_])ghs_[0-9]+_eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_.-])"#
        ) {
            result.append((.githubToken, regex))
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

        // GitHub Token - high confidence
        if let regex = githubClassicTokenRegex {
            result.append((.genericApiKey, regex))
        }

        // Stripe API Key - high confidence
        if let regex = stripeAPIKeyRegex {
            result.append((.genericApiKey, regex))
        }

        // Stripe Webhook Secret - high confidence
        // whsec_ prefix not covered by the generic sk/pk/api/key/token catch-all
        if let regex = stripeWebhookSecretRegex {
            result.append((.genericApiKey, regex))
        }

        // WO-487: broad prefixed lookalikes remain visible but advisory-only.
        // Keep this fallback after every sourced provider grammar.
        if let regex = try? NSRegularExpression(
            pattern: #"\b(sk|pk|api|key|token|secret|bearer)[_-][A-Za-z0-9]{20,}\b"#,
            options: [.caseInsensitive]
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
            // WO-390: allow multi-label service names while validation rejects
            // mixed-case dotted code identifiers.
            pattern: #"\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[-a-zA-Z0-9]+)+\.[a-zA-Z]{2,}\b"#,
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

        // WO-478/WO-479: payload-bearing formats must authorize complete secret
        // ranges before ordinary regex rules can claim marker-only success.
        scanGCPServiceAccountSecrets(content, config: config, matches: &matches, matchedRanges: &matchedRanges)
        scanCompletePrivateKeyBlocks(content, config: config, matches: &matches, matchedRanges: &matchedRanges)

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
                matches.append(DetectedMatch(
                    type: type,
                    value: value,
                    range: range,
                    line: line,
                    mutationAuthorizationSources: mutationAuthorizationSources(for: type, value: value)
                ))
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

    // WO-487/WO-488: genericApiKey provider evidence is attached to exact grammars;
    // dedicated intrinsic types are authorized centrally by DetectedMatch.init.
    private static func mutationAuthorizationSources(
        for type: SensitiveDataType,
        value: String
    ) -> Set<MutationAuthorizationSource> {
        guard type == .genericApiKey else { return [] }
        let range = NSRange(value.startIndex..., in: value)
        let sourcedRegexes = [
            githubClassicTokenRegex,
            stripeAPIKeyRegex,
            stripeWebhookSecretRegex,
        ].compactMap { $0 }
        let isSourcedProviderToken = sourcedRegexes.contains { regex in
            regex.firstMatch(in: value, options: [], range: range)?.range == range
        }
        return isSourcedProviderToken ? [.intrinsicFormat] : []
    }

    // WO-478: valid blocks authorize complete containment; malformed recognized
    // blocks reserve their bounded region as advisory-only evidence.
    private static func scanCompletePrivateKeyBlocks(
        _ content: String,
        config: PastewatchConfig,
        matches: inout [DetectedMatch],
        matchedRanges: inout [Range<String.Index>]
    ) {
        let labelPattern = "RSA PRIVATE KEY|DSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY|PRIVATE KEY"
        guard config.isTypeEnabled(.sshPrivateKey),
              let beginRegex = try? NSRegularExpression(pattern: "-----BEGIN (\(labelPattern))-----"),
              let endRegex = try? NSRegularExpression(pattern: "-----END (\(labelPattern))-----") else { return }

        let fullRange = NSRange(content.startIndex..., in: content)
        let beginCandidates = beginRegex.matches(in: content, range: fullRange)
        let endCandidates = endRegex.matches(in: content, range: fullRange)
        var malformedSuppressionEnd: String.Index?
        var endCandidateIndex = 0
        for (candidateIndex, candidate) in beginCandidates.enumerated() {
            guard let beginRange = Range(candidate.range, in: content),
                  let labelRange = Range(candidate.range(at: 1), in: content) else { continue }
            let searchLimit = content.index(
                beginRange.lowerBound,
                offsetBy: maximumPrivateKeyBlockCharacters,
                limitedBy: content.endIndex
            ) ?? content.endIndex
            let nextBeginRange = candidateIndex + 1 < beginCandidates.count
                ? Range(beginCandidates[candidateIndex + 1].range, in: content)
                : nil
            while endCandidateIndex < endCandidates.count,
                  endCandidates[endCandidateIndex].range.location <= candidate.range.location {
                endCandidateIndex += 1
            }
            let firstEndCandidate = endCandidateIndex < endCandidates.count
                ? endCandidates[endCandidateIndex]
                : nil
            let firstEndRange = firstEndCandidate.flatMap { Range($0.range, in: content) }
            let firstEndLabel = firstEndCandidate.flatMap { Range($0.range(at: 1), in: content) }
                .map { String(content[$0]) }
            let isSuppressed = malformedSuppressionEnd.map { beginRange.lowerBound < $0 } ?? false
            if isSuppressed { continue }
            let hasNestedBegin = nextBeginRange.map { nextBegin in
                firstEndRange.map { nextBegin.lowerBound < $0.lowerBound } ?? true
            } ?? false
            let isCorrectEnd = firstEndLabel == String(content[labelRange])
            let isWithinBound = firstEndRange.map { $0.upperBound <= searchLimit } ?? false

            guard !hasNestedBegin, isCorrectEnd, isWithinBound,
                  let endRange = firstEndRange else {
                let malformedEnd = firstEndRange?.upperBound ?? searchLimit
                let malformedRange = beginRange.lowerBound..<max(beginRange.upperBound, malformedEnd)
                malformedSuppressionEnd = max(malformedSuppressionEnd ?? beginRange.upperBound, malformedEnd)
                matches.removeAll { $0.range.overlaps(malformedRange) }
                matchedRanges.removeAll { $0.overlaps(malformedRange) }
                matches.append(DetectedMatch(
                    type: .sshPrivateKey,
                    value: String(content[beginRange]),
                    range: malformedRange,
                    line: lineNumber(of: beginRange.lowerBound, in: content),
                    advisory: .malformedPrivateKey
                ))
                matchedRanges.append(malformedRange)
                continue
            }

            let blockRange = beginRange.lowerBound..<endRange.upperBound
            guard !matchedRanges.contains(where: { $0.overlaps(blockRange) }) else { continue }

            let value = String(content[blockRange])
            matches.append(DetectedMatch(
                type: .sshPrivateKey,
                value: value,
                range: blockRange,
                line: lineNumber(of: blockRange.lowerBound, in: content)
            ))
            matchedRanges.append(blockRange)
        }
    }

    // WO-479: JSON structure proves context; only private_key and private_key_id
    // values become mutation-authorized matches. The service-account marker remains.
    private static func scanGCPServiceAccountSecrets(
        _ content: String,
        config: PastewatchConfig,
        matches: inout [DetectedMatch],
        matchedRanges: inout [Range<String.Index>]
    ) {
        guard config.isTypeEnabled(.gcpServiceAccount),
              (try? JSONSerialization.jsonObject(with: Data(content.utf8))) != nil else { return }
        var parser = JSONSourceRangeParser(content: content)
        guard let root = parser.parseDocument() else { return }
        var authorizedRanges: [Range<String.Index>] = []
        collectGCPServiceAccountRanges(root, into: &authorizedRanges)

        for valueRange in authorizedRanges where !matchedRanges.contains(where: { $0.overlaps(valueRange) }) {
            let encoded = String(content[valueRange])
            matches.append(DetectedMatch(
                type: .gcpServiceAccount,
                value: encoded,
                range: valueRange,
                line: lineNumber(of: valueRange.lowerBound, in: content)
            ))
            matchedRanges.append(valueRange)
        }
    }

    // WO-479: collect source ranges from the same object that carries the direct
    // service-account marker; equal decoded values elsewhere grant no authority.
    private static func collectGCPServiceAccountRanges(
        _ value: JSONSourceValue,
        into result: inout [Range<String.Index>]
    ) {
        switch value {
        case .object(let members):
            let directType = members.last { $0.key == "type" }?.value.stringValue
            if directType?.decoded == "service_account" {
                for member in members where member.key == "private_key" || member.key == "private_key_id" {
                    if let secret = member.value.stringValue, !secret.decoded.isEmpty {
                        result.append(secret.contentRange)
                    }
                }
            }
            for member in members {
                collectGCPServiceAccountRanges(member.value, into: &result)
            }
        case .array(let values):
            for child in values {
                collectGCPServiceAccountRanges(child, into: &result)
            }
        case .string, .scalar:
            break
        }
    }

    private struct JSONSourceString {
        let decoded: String
        let contentRange: Range<String.Index>
    }

    private struct JSONSourceMember {
        let key: String
        let value: JSONSourceValue
    }

    private indirect enum JSONSourceValue {
        case object([JSONSourceMember])
        case array([JSONSourceValue])
        case string(JSONSourceString)
        case scalar

        var stringValue: JSONSourceString? {
            guard case .string(let value) = self else { return nil }
            return value
        }
    }

    // WO-479: JSONSerialization proves validity; this deterministic companion
    // parser retains exact raw string ranges needed for context-bound mutation.
    private struct JSONSourceRangeParser {
        let content: String
        var index: String.Index

        init(content: String) {
            self.content = content
            self.index = content.startIndex
        }

        mutating func parseDocument() -> JSONSourceValue? {
            skipWhitespace()
            guard let value = parseValue() else { return nil }
            skipWhitespace()
            return index == content.endIndex ? value : nil
        }

        private mutating func parseValue() -> JSONSourceValue? {
            skipWhitespace()
            guard index < content.endIndex else { return nil }
            switch content[index] {
            case "{": return parseObject()
            case "[": return parseArray()
            case "\"": return parseString().map(JSONSourceValue.string)
            default: return parseScalar()
            }
        }

        private mutating func parseObject() -> JSONSourceValue? {
            advance()
            skipWhitespace()
            var members: [JSONSourceMember] = []
            if consume("}") { return .object(members) }

            while true {
                guard let key = parseString() else { return nil }
                skipWhitespace()
                guard consume(":") else { return nil }
                guard let value = parseValue() else { return nil }
                members.append(JSONSourceMember(key: key.decoded, value: value))
                skipWhitespace()
                if consume("}") { return .object(members) }
                guard consume(",") else { return nil }
                skipWhitespace()
            }
        }

        private mutating func parseArray() -> JSONSourceValue? {
            advance()
            skipWhitespace()
            var values: [JSONSourceValue] = []
            if consume("]") { return .array(values) }

            while true {
                guard let value = parseValue() else { return nil }
                values.append(value)
                skipWhitespace()
                if consume("]") { return .array(values) }
                guard consume(",") else { return nil }
                skipWhitespace()
            }
        }

        private mutating func parseString() -> JSONSourceString? {
            guard consume("\"") else { return nil }
            let contentStart = index
            while index < content.endIndex {
                let character = content[index]
                if character == "\"" {
                    let range = contentStart..<index
                    advance()
                    guard let decoded = decodeJSONStringContent(String(content[range])) else { return nil }
                    return JSONSourceString(decoded: decoded, contentRange: range)
                }
                if character == "\\" {
                    advance()
                    guard index < content.endIndex else { return nil }
                }
                advance()
            }
            return nil
        }

        private mutating func parseScalar() -> JSONSourceValue? {
            let start = index
            while index < content.endIndex,
                  ![",", "]", "}", " ", "\t", "\r", "\n"].contains(content[index]) {
                advance()
            }
            return start == index ? nil : .scalar
        }

        private mutating func skipWhitespace() {
            while index < content.endIndex, [" ", "\t", "\r", "\n"].contains(content[index]) {
                advance()
            }
        }

        private mutating func consume(_ expected: Character) -> Bool {
            guard index < content.endIndex, content[index] == expected else { return false }
            advance()
            return true
        }

        private mutating func advance() {
            index = content.index(after: index)
        }
    }

    private static func decodeJSONStringContent(_ encoded: String) -> String? {
        let wrapped = "\"\(encoded)\""
        return (try? JSONSerialization.jsonObject(
            with: Data(wrapped.utf8),
            options: [.fragmentsAllowed]
        )) as? String
    }

    /// WO-124: scan file IO using built-ins plus shared/generated pattern artifacts.
    public static func scanFileIO(_ content: String, config: PastewatchConfig) -> [DetectedMatch] {
        scanFileIOResult(content, config: config).matches
    }

    /// WO-126: scan file IO while preserving configured shared-pattern load diagnostics.
    public static func scanFileIOResult(
        _ content: String,
        config: PastewatchConfig,
        customRules: [CustomRule] = []
    ) -> FileIOScanResult {
        let sharedRuleSet = SharedSecretPatternSource.fileIORuleSet(for: config)
        let fileIORules = sharedRuleSet.rules + customRules
        guard !fileIORules.isEmpty else {
            return FileIOScanResult(
                matches: scan(content, config: config),
                sharedPatternErrors: sharedRuleSet.errors
            )
        }
        return FileIOScanResult(
            matches: scan(content, config: config, customRules: fileIORules),
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
    public static func scanFileIOOrThrow(
        _ content: String,
        config: PastewatchConfig,
        customRules: [CustomRule] = []
    ) throws -> [DetectedMatch] {
        let result = scanFileIOResult(content, config: config, customRules: customRules)
        guard !result.hasSharedPatternErrors else {
            throw sharedPatternLoadError(from: result.sharedPatternErrors)
        }
        return result.matches
    }

    /// WO-128: let scanner surfaces fail before returning partial shared-pattern coverage.
    public static func ensureSharedPatternsLoaded(config: PastewatchConfig) throws {
        let errors = SharedSecretPatternSource.fileIORuleSet(for: config).errors
        guard errors.isEmpty else {
            throw sharedPatternLoadError(from: errors)
        }
    }

    private static func sharedPatternLoadError(from errors: [SharedSecretPatternLoadError]) -> SharedSecretPatternLoadError {
        SharedSecretPatternLoadError(
            path: "sharedPatternFiles",
            message: errors.map(\.localizedDescription).joined(separator: "; ")
        )
    }

    // WO-478: malformed container evidence overrides overlapping mutation rules.
    /// Scan with allowlist filtering and custom rules.
    public static func scan(
        _ content: String,
        config: PastewatchConfig,
        allowlist: Allowlist = Allowlist(),
        customRules: [CustomRule] = [],
        knownSecretValues: Set<String> = []
    ) -> [DetectedMatch] {
        var matches: [DetectedMatch] = []
        var matchedRanges: [Range<String.Index>] = []

        // WO-404: custom rules are explicit operator approval, so they promote
        // overlapping uncertain built-ins into mutation-safe matches.
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

        for match in scan(content, config: config) {
            // WO-478: malformed private-key evidence overrides overlapping custom
            // matches so malformed input cannot be reported as successful mutation.
            if match.advisory != nil {
                matches.removeAll { $0.range.overlaps(match.range) }
                matchedRanges.removeAll { $0.overlaps(match.range) }
            } else if let index = matches.firstIndex(where: { $0.range == match.range }) {
                // WO-454: an exact built-in/custom overlap retains evidence from both
                // detectors instead of allowing deduplication to weaken authorization.
                matches[index] = matches[index].addingMutationAuthorizationSources(
                    match.mutationAuthorizationSources
                )
                continue
            } else if matchedRanges.contains(where: { $0.overlaps(match.range) }) {
                continue
            }
            matches.append(match)
            matchedRanges.append(match.range)
        }

        // Apply allowlist filtering
        if !allowlist.values.isEmpty || !allowlist.patterns.isEmpty {
            matches = allowlist.filter(matches)
        }

        if !knownSecretValues.isEmpty {
            matches = matches.map { match in
                guard knownSecretValues.contains(match.value), match.advisory == nil else { return match }
                return match.addingMutationAuthorizationSources([.exactKnownSecret])
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
        let key = String(fullMatch[..<separatorRange.lowerBound])
            .trimmingCharacters(in: .whitespaces)
        let separator = String(fullMatch[separatorRange])
        let value = String(fullMatch[separatorRange.upperBound...])
            .trimmingCharacters(in: .whitespaces)

        // WO-390@v2: source assignments and schema labels can carry code references,
        // while values with deterministic secret evidence must remain detectable.
        if isLikelyStructFieldReference(key: key, separator: separator, value: value) {
            return false
        }

        return isValidCredentialValue(value)
    }

    // WO-390@v2: classify source-language references by value shape, not key casing.
    private static func isLikelyStructFieldReference(key: String, separator: String, value: String) -> Bool {
        let separatorText = separator.trimmingCharacters(in: .whitespaces)
        guard [":", "=", ":="].contains(separatorText), !key.isEmpty else { return false }

        let trailingSyntax = CharacterSet.whitespacesAndNewlines
            .union(CharacterSet(charactersIn: ",;\"'`"))
        let cleanedValue = value.trimmingCharacters(in: trailingSyntax)
        let identifierPattern = #"^[A-Za-z_][A-Za-z0-9_]*$"#
        let dottedIdentifierPattern = #"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"#
        let callPattern = #"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\([^)]*\)$"#

        if cleanedValue.range(of: callPattern, options: .regularExpression) != nil ||
            cleanedValue.range(of: dottedIdentifierPattern, options: .regularExpression) != nil {
            return true
        }

        guard cleanedValue.range(of: identifierPattern, options: .regularExpression) != nil else {
            return false
        }
        return !hasDeterministicCredentialEvidence(cleanedValue)
    }

    // WO-390@v2: preserve generic credential findings only when the value itself
    // carries deterministic evidence beyond being a source-language identifier.
    private static func hasDeterministicCredentialEvidence(_ value: String) -> Bool {
        let lowerValue = value.lowercased()
        let hasDigit = value.contains(where: \.isNumber)
        if hasDigit {
            return true
        }

        let hasUnderscore = value.contains("_")
        let credentialMarkers = ["password", "passwd", "secret", "token", "api_key", "apikey"]
        if hasUnderscore && credentialMarkers.contains(where: lowerValue.contains) {
            return true
        }

        return value.count >= minimumEntropyLength && shannonEntropy(value) >= entropyThreshold
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
    public static func isValidCredentialValue(_ value: String) -> Bool {
        // WO-122: matched shell quotes should not hide env-var references from the prefix gate.
        let credentialValue: String
        if value.count >= 2,
           let first = value.first,
           let last = value.last,
           first == last,
           first == "\"" || first == "'" {
            credentialValue = String(value.dropFirst().dropLast())
        } else {
            credentialValue = value
        }

        // Too short to be a real secret
        if credentialValue.count < 4 { return false }

        // Skip env var references ($VAR, ${VAR}, %VAR%)
        if credentialValue.hasPrefix("$") || credentialValue.hasPrefix("%") { return false }

        // Skip common documentation/prose words after credential keywords
        let lowerValue = credentialValue.lowercased()
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
        let hasDigit = credentialValue.contains(where: { $0.isNumber })
        let hasUpper = credentialValue.contains(where: { $0.isUppercase })
        let hasSpecial = credentialValue.contains(where: { "!@#$%^&*()_+-=[]{}|;:',.<>?/`~".contains($0) })
        let isAllLowerAlpha = credentialValue.allSatisfy { $0.isLowercase || $0 == "-" || $0 == "_" }

        // Pure lowercase word without digits or special chars is likely prose
        if isAllLowerAlpha && !hasDigit && !hasSpecial && credentialValue.count < 20 { return false }

        // At least two of: digits, uppercase, special chars → likely a real secret
        let complexityScore = (hasDigit ? 1 : 0) + (hasUpper ? 1 : 0) + (hasSpecial ? 1 : 0)
        if complexityScore == 0 && credentialValue.count < 20 { return false }

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
        // WO-390: Go method chains such as node.HostStartedAt.IsZero match the
        // FQDN regex shape but include mixed-case code identifiers.
        if isLikelyDottedCodeIdentifier(value) { return false }
        return true
    }

    private static func isLikelyDottedCodeIdentifier(_ value: String) -> Bool {
        let segments = value.split(separator: ".")
        guard segments.count >= 3 else { return false }
        return segments.contains { segment in
            let scalars = segment.unicodeScalars
            let hasUppercase = scalars.contains { CharacterSet.uppercaseLetters.contains($0) }
            let hasLowercase = scalars.contains { CharacterSet.lowercaseLetters.contains($0) }
            return hasUppercase && hasLowercase
        }
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
