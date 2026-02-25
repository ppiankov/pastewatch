import XCTest
@testable import PastewatchCore

final class DetectionRulesTests: XCTestCase {
    let config = PastewatchConfig.defaultConfig

    // MARK: - Email Detection

    func testDetectsEmail() {
        let content = "Contact me at john.doe@company.com for details"
        let matches = DetectionRules.scan(content, config: config)

        XCTAssertEqual(matches.count, 1)
        XCTAssertEqual(matches.first?.type, .email)
        XCTAssertEqual(matches.first?.value, "john.doe@company.com")
    }

    func testDetectsMultipleEmails() {
        let content = "Send to alice@example.org and bob@test.net"
        let matches = DetectionRules.scan(content, config: config)

        XCTAssertEqual(matches.count, 2)
        XCTAssertTrue(matches.allSatisfy { $0.type == .email })
    }

    // MARK: - Phone Detection

    func testDetectsInternationalPhone() {
        let content = "Call me at +60123456789"
        let matches = DetectionRules.scan(content, config: config)

        let phoneMatches = matches.filter { $0.type == .phone }
        XCTAssertGreaterThanOrEqual(phoneMatches.count, 1)
    }

    func testDetectsUSPhone() {
        let content = "My number is (555) 123-4567"
        let matches = DetectionRules.scan(content, config: config)

        let phoneMatches = matches.filter { $0.type == .phone }
        XCTAssertGreaterThanOrEqual(phoneMatches.count, 1)
    }

    // MARK: - IP Address Detection

    func testDetectsIPAddress() {
        let content = "Server is at 192.168.1.100"
        let matches = DetectionRules.scan(content, config: config)

        XCTAssertEqual(matches.count, 1)
        XCTAssertEqual(matches.first?.type, .ipAddress)
        XCTAssertEqual(matches.first?.value, "192.168.1.100")
    }

    func testExcludesLocalhost() {
        let content = "Running on 127.0.0.1"
        let matches = DetectionRules.scan(content, config: config)

        // Should not match localhost
        let ipMatches = matches.filter { $0.type == .ipAddress }
        XCTAssertEqual(ipMatches.count, 0)
    }

    // MARK: - AWS Key Detection

    func testDetectsAWSAccessKeyID() {
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        let matches = DetectionRules.scan(content, config: config)

        let awsMatches = matches.filter { $0.type == .awsKey }
        XCTAssertGreaterThanOrEqual(awsMatches.count, 1)
        XCTAssertTrue(awsMatches.first?.value.hasPrefix("AKIA") ?? false)
    }

    // MARK: - API Key Detection

    func testDetectsGitHubToken() {
        let content = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        let matches = DetectionRules.scan(content, config: config)

        let apiKeyMatches = matches.filter { $0.type == .genericApiKey }
        XCTAssertGreaterThanOrEqual(apiKeyMatches.count, 1)
    }

    func testDetectsGenericSecretKey() {
        // Test generic secret_ prefix pattern (avoids GitHub secret scanning)
        let content = "my_secret: secret_abcdefghijklmnopqrstuvwxyz"
        let matches = DetectionRules.scan(content, config: config)

        let apiKeyMatches = matches.filter { $0.type == .genericApiKey }
        XCTAssertGreaterThanOrEqual(apiKeyMatches.count, 1)
    }

    // MARK: - UUID Detection

    func testDetectsUUID() {
        let content = "User ID: 550e8400-e29b-41d4-a716-446655440000"
        let matches = DetectionRules.scan(content, config: config)

        let uuidMatches = matches.filter { $0.type == .uuid }
        XCTAssertEqual(uuidMatches.count, 1)
        XCTAssertEqual(uuidMatches.first?.value, "550e8400-e29b-41d4-a716-446655440000")
    }

    // MARK: - Database Connection String Detection

    func testDetectsPostgresConnectionString() {
        let content = "DATABASE_URL=postgres://user:pass@host:5432/db"
        let matches = DetectionRules.scan(content, config: config)

        let dbMatches = matches.filter { $0.type == .dbConnectionString }
        XCTAssertGreaterThanOrEqual(dbMatches.count, 1)
    }

    func testDetectsMongoDBConnectionString() {
        let content = "MONGO_URI=mongodb://user:pass@host:27017/db"
        let matches = DetectionRules.scan(content, config: config)

        let dbMatches = matches.filter { $0.type == .dbConnectionString }
        XCTAssertGreaterThanOrEqual(dbMatches.count, 1)
    }

    // MARK: - JWT Detection

    func testDetectsJWT() {
        let content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        let matches = DetectionRules.scan(content, config: config)

        let jwtMatches = matches.filter { $0.type == .jwtToken }
        XCTAssertGreaterThanOrEqual(jwtMatches.count, 1)
    }

    // MARK: - Credit Card Detection

    func testDetectsVisaCard() {
        let content = "Card: 4111111111111111"
        let matches = DetectionRules.scan(content, config: config)

        let cardMatches = matches.filter { $0.type == .creditCard }
        XCTAssertEqual(cardMatches.count, 1)
    }

    func testDetectsMastercardWithSpaces() {
        let content = "Pay with 5500 0000 0000 0004"
        let matches = DetectionRules.scan(content, config: config)

        let cardMatches = matches.filter { $0.type == .creditCard }
        XCTAssertEqual(cardMatches.count, 1)
    }

    func testRejectsInvalidLuhnCard() {
        let content = "Invalid: 4111111111111112"
        let matches = DetectionRules.scan(content, config: config)

        let cardMatches = matches.filter { $0.type == .creditCard }
        XCTAssertEqual(cardMatches.count, 0)
    }

    // MARK: - SSH Key Detection

    func testDetectsSSHPrivateKey() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        let matches = DetectionRules.scan(content, config: config)

        let sshMatches = matches.filter { $0.type == .sshPrivateKey }
        XCTAssertGreaterThanOrEqual(sshMatches.count, 1)
    }

    // MARK: - No False Positives

    func testNoFalsePositivesOnCleanText() {
        let content = "Hello, this is a normal message without any sensitive data."
        let matches = DetectionRules.scan(content, config: config)

        XCTAssertEqual(matches.count, 0)
    }

    func testNoFalsePositivesOnCode() {
        let content = """
        func main() {
            let x = 42
            print("Hello, World!")
        }
        """
        let matches = DetectionRules.scan(content, config: config)

        XCTAssertEqual(matches.count, 0)
    }

    // MARK: - File Path Detection

    func testDetectsLinuxFilePath() {
        let content = "Config at /etc/nginx/nginx.conf"
        let matches = DetectionRules.scan(content, config: config)

        let pathMatches = matches.filter { $0.type == .filePath }
        XCTAssertEqual(pathMatches.count, 1)
    }

    func testDetectsHomePath() {
        let content = "SSH key at /home/deploy/.ssh/id_rsa"
        let matches = DetectionRules.scan(content, config: config)

        let pathMatches = matches.filter { $0.type == .filePath }
        XCTAssertGreaterThanOrEqual(pathMatches.count, 1)
    }

    func testIgnoresShortPath() {
        let content = "Found in /tmp/x"
        let matches = DetectionRules.scan(content, config: config)

        let pathMatches = matches.filter { $0.type == .filePath }
        // Too short — only 2 components (tmp, x)
        XCTAssertEqual(pathMatches.count, 0)
    }

    // MARK: - Hostname Detection

    func testDetectsInternalHostname() {
        let content = "Connect to db-primary.internal.corp.net"
        let matches = DetectionRules.scan(content, config: config)

        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertGreaterThanOrEqual(hostMatches.count, 1)
    }

    func testIgnoresSafeHosts() {
        let content = "Visit github.com for source"
        let matches = DetectionRules.scan(content, config: config)

        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 0)
    }

    func testIgnoresExampleDotCom() {
        let content = "See example.com for docs"
        let matches = DetectionRules.scan(content, config: config)

        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 0)
    }

    // MARK: - Credential Detection

    func testDetectsPasswordKeyValue() {
        let content = "password=s3cret_value"
        let matches = DetectionRules.scan(content, config: config)

        let credMatches = matches.filter { $0.type == .credential }
        XCTAssertEqual(credMatches.count, 1)
    }

    func testDetectsSecretColonValue() {
        let content = "secret: my_api_secret_123"
        let matches = DetectionRules.scan(content, config: config)

        let credMatches = matches.filter { $0.type == .credential }
        XCTAssertGreaterThanOrEqual(credMatches.count, 1)
    }

    func testDetectsTokenAssignment() {
        let content = "auth=bearer_token_xyz123"
        let matches = DetectionRules.scan(content, config: config)

        let credMatches = matches.filter { $0.type == .credential }
        XCTAssertGreaterThanOrEqual(credMatches.count, 1)
    }

    // MARK: - Slack Webhook Detection

    func testDetectsSlackWebhook() {
        let content = "WEBHOOK=https://hooks.slack.com/services/T1234ABCD/B5678EFGH/abcdefghijklmnop"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .slackWebhook })
    }

    func testSlackWebhookRequiresFullURL() {
        let content = "https://hooks.slack.com/services/"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .slackWebhook })
    }

    // MARK: - Discord Webhook Detection

    func testDetectsDiscordWebhook() {
        let content = "url: https://discord.com/api/webhooks/123456789012345678/abcDEF_ghi-jklMNO123"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .discordWebhook })
    }

    func testDiscordWebhookRequiresToken() {
        let content = "https://discord.com/api/webhooks/"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .discordWebhook })
    }

    // MARK: - Azure Connection String Detection

    func testDetectsAzureConnectionString() {
        let content = "ConnectionString=DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456+ghi789=="
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .azureConnectionString })
    }

    func testAzureConnectionStringRequiresAccountKey() {
        let content = "DefaultEndpointsProtocol=https;AccountName=myaccount"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .azureConnectionString })
    }

    // MARK: - GCP Service Account Detection

    func testDetectsGCPServiceAccount() {
        let content = """
        {"type": "service_account", "project_id": "my-project"}
        """
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .gcpServiceAccount })
    }

    func testDetectsGCPServiceAccountWithSpacing() {
        let content = #""type" :  "service_account""#
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .gcpServiceAccount })
    }

    // MARK: - ClickHouse Connection String Detection

    func testDetectsClickHouseConnectionString() {
        let content = "CH_URL=clickhouse://user:pass@host:9000/db"
        let matches = DetectionRules.scan(content, config: config)
        let dbMatches = matches.filter { $0.type == .dbConnectionString }
        XCTAssertGreaterThanOrEqual(dbMatches.count, 1)
    }

    // MARK: - OpenAI Key Detection

    // Test values use string concatenation to avoid triggering pre-commit hooks
    private static let skProj = "sk-" + "proj-"
    private static let skSvcacct = "sk-" + "svcacct-"
    private static let skAntApi = "sk-" + "ant-api03-"
    private static let skAntAdmin = "sk-" + "ant-admin01-"
    private static let testSuffix = "abc123def456ghi789jkl012mno345"

    func testDetectsOpenAIProjectKey() {
        let content = "OPENAI_KEY=" + Self.skProj + Self.testSuffix
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .openaiKey })
    }

    func testDetectsOpenAIServiceAccountKey() {
        let content = "key: " + Self.skSvcacct + Self.testSuffix
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .openaiKey })
    }

    func testOpenAIKeyNotMatchedAsGenericApiKey() {
        let content = Self.skProj + Self.testSuffix
        let matches = DetectionRules.scan(content, config: config)
        // Should match as OpenAI, not generic API key
        XCTAssertTrue(matches.contains { $0.type == .openaiKey })
        XCTAssertFalse(matches.contains { $0.type == .genericApiKey })
    }

    // MARK: - Anthropic Key Detection

    func testDetectsAnthropicApiKey() {
        let content = "ANTHROPIC_KEY=" + Self.skAntApi + Self.testSuffix
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .anthropicKey })
    }

    func testDetectsAnthropicAdminKey() {
        let content = "key=" + Self.skAntAdmin + Self.testSuffix
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .anthropicKey })
    }

    func testAnthropicKeyNotMatchedAsGenericApiKey() {
        let content = Self.skAntApi + Self.testSuffix
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .anthropicKey })
        XCTAssertFalse(matches.contains { $0.type == .genericApiKey })
    }

    // MARK: - Hugging Face Token Detection

    func testDetectsHuggingFaceToken() {
        let content = "HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .huggingfaceToken })
    }

    func testHuggingFaceTokenTooShort() {
        let content = "hf_short"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .huggingfaceToken })
    }

    // MARK: - Groq Key Detection

    func testDetectsGroqKey() {
        let content = "GROQ_KEY=gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .groqKey })
    }

    func testGroqKeyTooShort() {
        let content = "gsk_short"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .groqKey })
    }

    // MARK: - npm Token Detection

    func testDetectsNpmToken() {
        let content = "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .npmToken })
    }

    func testNpmTokenTooShort() {
        let content = "npm_short"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .npmToken })
    }

    // MARK: - PyPI Token Detection

    func testDetectsPyPIToken() {
        let content = "PYPI_TOKEN=pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .pypiToken })
    }

    func testPyPITokenTooShort() {
        let content = "pypi-short"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .pypiToken })
    }

    // MARK: - RubyGems Token Detection

    func testDetectsRubyGemsToken() {
        let content = "GEM_TOKEN=rubygems_ABCDEFGHIJKLMNOPQRSTUVWXYZab"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .rubygemsToken })
    }

    func testRubyGemsTokenTooShort() {
        let content = "rubygems_short"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .rubygemsToken })
    }

    // MARK: - GitLab Token Detection

    func testDetectsGitLabToken() {
        let content = "GITLAB_TOKEN=glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .gitlabToken })
    }

    func testGitLabTokenTooShort() {
        let content = "glpat-short"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .gitlabToken })
    }

    // MARK: - Telegram Bot Token Detection

    func testDetectsTelegramBotToken() {
        let content = "BOT_TOKEN=123456789:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .telegramBotToken })
    }

    func testTelegramBotTokenWrongFormat() {
        // Too few digits before colon
        let content = "12345:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .telegramBotToken })
    }

    // MARK: - SendGrid Key Detection

    func testDetectsSendGridKey() {
        let content = "SENDGRID_KEY=SG.abcdefghijklmnopqrstuvwx.ABCDEFGHIJKLMNOPQRSTUVWXyz012345"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .sendgridKey })
    }

    func testSendGridKeyMissingSecondSegment() {
        let content = "SG.abcdefghijklmnopqrstuvwx"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .sendgridKey })
    }

    // MARK: - Shopify Token Detection

    func testDetectsShopifyAccessToken() {
        let content = "SHOPIFY_TOKEN=shpat_abcdef0123456789abcdef01"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .shopifyToken })
    }

    func testDetectsShopifyCustomAppToken() {
        let content = "token: shpca_abcdef0123456789abcdef01"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .shopifyToken })
    }

    func testShopifyTokenTooShort() {
        let content = "shpat_abc"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .shopifyToken })
    }

    // MARK: - DigitalOcean Token Detection

    func testDetectsDigitalOceanPersonalToken() {
        let content = "DO_TOKEN=dop_v1_" + String(repeating: "a1b2c3d4", count: 8)
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .digitaloceanToken })
    }

    func testDetectsDigitalOceanOAuthToken() {
        let content = "DO_TOKEN=doo_v1_" + String(repeating: "a1b2c3d4", count: 8)
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .digitaloceanToken })
    }

    func testDigitalOceanTokenWrongLength() {
        let content = "dop_v1_abcdef1234"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .digitaloceanToken })
    }

    // MARK: - Line Number Tracking

    func testLineNumbersOnMultilineContent() {
        let content = "First line is clean\nSecond has test@corp.com\nThird line\nFourth has 192.168.1.50"
        let matches = DetectionRules.scan(content, config: config)

        let emailMatch = matches.first { $0.type == .email }
        XCTAssertEqual(emailMatch?.line, 2)

        let ipMatch = matches.first { $0.type == .ipAddress }
        XCTAssertEqual(ipMatch?.line, 4)
    }

    func testLineNumberSingleLine() {
        let content = "Server at 10.0.0.1"
        let matches = DetectionRules.scan(content, config: config)

        XCTAssertEqual(matches.first?.line, 1)
    }

    // MARK: - Config Filtering

    func testRespectsDisabledTypes() {
        var config = PastewatchConfig.defaultConfig
        config.enabledTypes = ["Phone"] // Only enable phone detection

        let content = "Email: test@example.com, Phone: +60123456789"
        let matches = DetectionRules.scan(content, config: config)

        // Should only detect phone, not email
        XCTAssertTrue(matches.allSatisfy { $0.type == .phone })
    }
}
