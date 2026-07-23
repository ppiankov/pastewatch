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

    // WO-485: preserve the established type for classic GitHub token prefixes.
    func testDetectsClassicGitHubTokenAsGenericAPIKey() {
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
        let content = pemFixture(
            label: "RSA PRIVATE KEY",
            payload: String(repeating: "QUJD", count: 12),
            newline: "\n"
        )
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

    func testIgnoresGoMethodChainsAsHostnames() {
        // WO-390: Go field/method chains are dotted code identifiers, not FQDNs.
        let methodChains = [
            "node.HostStartedAt.IsZero",
            "envelope.Topology.Band",
            "r.Wo.ID",
            "ask.Envelope.Delivery",
            "p.CreatedAt.Format",
        ]

        for content in methodChains {
            let matches = DetectionRules.scan(content, config: config)
            let hostMatches = matches.filter { $0.type == .hostname }
            XCTAssertEqual(hostMatches.count, 0, "Should not detect Go method chain as hostname: \(content)")
        }
    }

    func testStillDetectsServiceHostnames() {
        let content = "Connect to api.internal.corp and myservice.default.svc.cluster.local"
        let matches = DetectionRules.scan(content, config: config)

        let values = Set(matches.filter { $0.type == .hostname }.map(\.value))
        XCTAssertTrue(values.contains("api.internal.corp"))
        XCTAssertTrue(values.contains("myservice.default.svc.cluster.local"))
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

    // WO-122: matched single/double quotes around env refs must not turn refs into literals.
    func testIgnoresQuoteWrappedCredentialEnvReferences() {
        let cleanCases = [
            (name: "double-quoted dollar ref", source: #"api_key="$PTOK""#, value: #""$PTOK""#),
            (name: "double-quoted braced ref", source: #"secret="${VAULT_KEY}""#, value: #""${VAULT_KEY}""#),
            (name: "single-quoted dollar ref", source: "token='$X'", value: "'$X'"),
            (
                name: "double-quoted default expansion",
                source: #"password="${A:-fallback}""#,
                value: #""${A:-fallback}""#
            ),
            (name: "double-quoted percent ref", source: #"token="%VAR%""#, value: #""%VAR%""#),
            (name: "bare dollar ref", source: "api_key=$PTOK", value: "$PTOK"),
            (name: "bare braced ref", source: #"secret=${A}"#, value: "${A}"),
            (name: "bare percent ref", source: "token=%VAR%", value: "%VAR%"),
        ]

        for testCase in cleanCases {
            XCTAssertFalse(
                DetectionRules.isValidCredentialValue(testCase.value),
                "Should ignore credential value: \(testCase.name)"
            )
            let matches = DetectionRules.scan(testCase.source, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertEqual(credMatches.count, 0, "Should not detect credential: \(testCase.name)")
        }
    }

    // WO-122: stripping quotes must expose literals while backticks stay fail-closed.
    func testQuoteWrappedCredentialLiteralsStillDetected() {
        let literal = "Alpha" + String(repeating: "A1", count: 18) + "_tail"
        let literalCases = [
            (name: "bare literal", source: "api_key=\(literal)", value: literal),
            (name: "double-quoted literal", source: "api_key=\"\(literal)\"", value: "\"\(literal)\""),
            (name: "single-quoted literal", source: "api_key='\(literal)'", value: "'\(literal)'"),
            (name: "backtick literal", source: "api_key=`\(literal)`", value: "`\(literal)`"),
            (name: "leading-quote-only ref", source: "api_key=\"$PTOK", value: "\"$PTOK"),
        ]

        for testCase in literalCases {
            XCTAssertTrue(
                DetectionRules.isValidCredentialValue(testCase.value),
                "Should keep detecting credential value: \(testCase.name)"
            )
            let matches = DetectionRules.scan(testCase.source, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertGreaterThanOrEqual(credMatches.count, 1, "Should detect credential: \(testCase.name)")
        }
    }

    // MARK: - False Positive Exclusions

    func testIgnoresAuthBooleanValues() {
        let booleans = ["auth=true", "AUTH=false", "auth=1", "auth=0",
                        "auth=yes", "auth=no", "auth=none", "auth=null", "auth=nil"]
        for input in booleans {
            let matches = DetectionRules.scan(input, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertEqual(credMatches.count, 0, "Should not detect: \(input)")
        }
    }

    func testIgnoresGoEnvLookup() {
        let goPatterns = [
            "apiKey := os.Getenv(\"API_KEY\")",
            "secret = os.Getenv(\"SECRET\")",
            "token = os.Getenv(\"TOKEN\")"
        ]
        for input in goPatterns {
            let matches = DetectionRules.scan(input, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertEqual(credMatches.count, 0, "Should not detect Go env lookup: \(input)")
        }
    }

    func testIgnoresProcessEnvLookup() {
        let jsPatterns = [
            "const token = process.env.TOKEN",
            "password = process.env.DB_PASSWORD"
        ]
        for input in jsPatterns {
            let matches = DetectionRules.scan(input, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertEqual(credMatches.count, 0, "Should not detect env lookup: \(input)")
        }
    }

    func testIgnoresGoStructFieldReferencesAsCredentials() {
        // WO-390: exported Go struct fields with code-reference RHS values are not literals.
        let goFields = [
            "Token: makeToken(),",
            "Secret: computeSecret(),",
            "Credentials: creds,",
        ]

        for input in goFields {
            let matches = DetectionRules.scan(input, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertEqual(credMatches.count, 0, "Should not detect Go field reference: \(input)")
        }
    }

    // WO-390@v2: lowercase Go and Python assignments can carry code references, not secrets.
    func testIgnoresLowercaseCodeReferenceAssignmentsAsCredentials() {
        let codeReferences = [
            "token = parse()",
            "auth_token = args.small_p95_slo_seconds",
            "api_key = options.apiKey",
            "credentials := requestCredentials()",
            "secret = computedValue",
            "token = arg_small_p95",
            "secret = opt_v2",
        ]

        for input in codeReferences {
            let matches = DetectionRules.scan(input, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertEqual(credMatches.count, 0, "Should not detect code reference: \(input)")
        }
    }

    // WO-390@v2: schema instructions ending in an operator keyword are prose, not credentials.
    func testIgnoresStructTagCredentialKeywords() {
        let structTags = [
            #"`jsonschema:"description=confirmation token: MERGE"`"#,
            #"`jsonschema:"description=confirmation secret: DELETE"`"#,
        ]

        for input in structTags {
            let matches = DetectionRules.scan(input, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertEqual(credMatches.count, 0, "Should not detect struct-tag instruction: \(input)")
        }
    }

    // WO-390@v2: code-reference exclusions must not hide deterministic secret evidence.
    func testCodeReferenceExclusionsPreserveRealSecretShapes() {
        let password = "password=" + ["s3cret", "value", "123"].joined(separator: "_")
        let apiKey = "api_key=sk_live_" + String(repeating: "A1", count: 12)
        let token = "token=TokenValue" + String(repeating: "A1", count: 8)
        let userInfo = ["user", "pass"].joined(separator: ":")
        let dsn = "dsn=postgres://" + userInfo + "@db-primary.internal/app"
        let privateKey = "private_key=\n" + pemFixture(
            label: "PRIVATE KEY",
            payload: String(repeating: "QUJD", count: 12),
            newline: "\n"
        )
        let cases: [(String, SensitiveDataType)] = [
            (password, .credential),
            (apiKey, .genericApiKey),
            (token, .credential),
            (dsn, .dbConnectionString),
            (privateKey, .sshPrivateKey),
        ]

        for (content, expectedType) in cases {
            let matches = DetectionRules.scan(content, config: config)
            XCTAssertTrue(
                matches.contains { $0.type == expectedType },
                "Should preserve \(expectedType.rawValue) detection"
            )
        }
    }

    func testIgnoresStandaloneFortyCharStrings() {
        // Go test function names, git SHAs, markdown paths — should NOT match AWS key
        let falsePositives = [
            "TestValidateAgentUpdatesNormalizesValues",
            "func TestHandleAcknowledgeResponseTimeout()",
            "/adoption/regret/performance/operational"
        ]
        for input in falsePositives {
            let matches = DetectionRules.scan(input, config: config)
            let awsMatches = matches.filter { $0.type == .awsKey }
            XCTAssertEqual(awsMatches.count, 0, "Should not detect as AWS key: \(input)")
        }
    }

    func testStillDetectsRealAwsSecretKey() {
        let input = ["aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfi",
                     "CYEXAMPLEKEY"].joined()
        let matches = DetectionRules.scan(input, config: config)
        let awsMatches = matches.filter { $0.type == .awsKey }
        XCTAssertGreaterThanOrEqual(awsMatches.count, 1)
    }

    func testStillDetectsRealCredentials() {
        let realSecrets = [
            "password=s3cret_value_123",
            "secret: my_api_secret_xyz",
            "api_key=sk_live_abc123def456"
        ]
        for input in realSecrets {
            let matches = DetectionRules.scan(input, config: config)
            let credMatches = matches.filter { $0.type == .credential }
            XCTAssertGreaterThanOrEqual(credMatches.count, 1, "Should detect: \(input)")
        }
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
        XCTAssertTrue(config.isTypeEnabled(.gcpServiceAccount))
        let content = #"{"type":"service_account","private_key_id":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}"#
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .gcpServiceAccount })
    }

    func testDetectsGCPServiceAccountWithSpacing() {
        let content = #"{"private_key_id" : "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", "type" : "service_account"}"#
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
    private static let skWS = "sk-" + "ws-"
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

    // WO-145: workspace-scoped DashScope keys are intrinsic provider tokens.
    func testDetectsDashScopeWorkspaceKeysWithoutGenericFallback() {
        let values = [
            Self.skWS + "abc." + String(repeating: "Q", count: 20),
            Self.skWS + "xyz." + String(repeating: "R", count: 32),
            Self.skWS + "abc." + String(repeating: "S", count: 10) + "-" + String(repeating: "T", count: 10),
        ]

        for value in values {
            let matches = DetectionRules.scan("DASHSCOPE_API_KEY=" + value, config: config)
            XCTAssertTrue(matches.contains { $0.type == .dashscopeKey && $0.value == value })
            XCTAssertFalse(matches.contains { $0.type == .genericApiKey && $0.value == value })
        }
    }

    // WO-145: reject short or unsegmented lookalikes.
    func testDashScopeWorkspaceKeyRequiresCompleteSegmentedPayload() {
        let short = Self.skWS + "abc." + String(repeating: "Q", count: 19)
        let unsegmented = Self.skWS + String(repeating: "Q", count: 30)

        XCTAssertFalse(DetectionRules.scan(short, config: config).contains { $0.type == .dashscopeKey })
        XCTAssertFalse(DetectionRules.scan(unsegmented, config: config).contains { $0.type == .dashscopeKey })
        XCTAssertTrue(DetectionRules.scan(Self.skAntApi + Self.testSuffix, config: config).contains {
            $0.type == .anthropicKey
        })
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

    // MARK: - Perplexity Key Detection

    func testDetectsPerplexityKey() {
        let content = "PPLX_KEY=pplx-" + String(repeating: "aB1cD2eF", count: 6)
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .perplexityKey })
    }

    func testPerplexityKeyWrongLength() {
        let content = "pplx-tooshort123"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .perplexityKey })
    }

    func testPerplexityKeySeverityIsCritical() {
        XCTAssertEqual(SensitiveDataType.perplexityKey.severity, .critical)
    }

    // MARK: - JDBC URL Detection

    func testDetectsJDBCOracleThin() {
        let content = "url=jdbc:oracle:thin:@dbhost.internal.com:1521:PRODDB"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl })
    }

    func testDetectsJDBCOracleThinServiceName() {
        let content = "jdbc:oracle:thin:@//dbhost.internal.com:1521/PRODDB"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl })
    }

    func testDetectsJDBCPostgreSQL() {
        let content = "jdbc:postgresql://db.internal.com:5432/mydb"
        let matches = DetectionRules.scan(content, config: config)
        // May match as dbConnectionString (postgresql://) or jdbcUrl — either is correct
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl || $0.type == .dbConnectionString })
    }

    func testDetectsJDBCMySQL() {
        let content = "jdbc:mysql://db.internal.com:3306/mydb?ssl=true"
        let matches = DetectionRules.scan(content, config: config)
        // May match as dbConnectionString (mysql://) or jdbcUrl — either is correct
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl || $0.type == .dbConnectionString })
    }

    func testDetectsJDBCSQLServer() {
        let content = "jdbc:sqlserver://db.internal.com:1433;databaseName=mydb"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl })
    }

    func testDetectsJDBCDB2() {
        let content = "jdbc:db2://db.internal.com:50000/mydb"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl })
    }

    func testDetectsJDBCAS400() {
        let content = "jdbc:as400://as400.internal.com/MYLIB"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl })
    }

    func testJDBCInSpringConfig() {
        let content = "spring.datasource.url=jdbc:oracle:thin:@prod-db:1521:FINDB"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .jdbcUrl })
    }

    func testNoFalsePositiveJDBCPrefix() {
        let content = "jdbc: is a standard"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .jdbcUrl })
    }

    func testJDBCSeverityIsCritical() {
        XCTAssertEqual(SensitiveDataType.jdbcUrl.severity, .critical)
    }

    // MARK: - XML Credential Detection

    func testDetectsXMLPasswordTag() {
        let content = "<password>my_secret_pass</password>"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .xmlCredential })
    }

    func testDetectsXMLPasswordSHA256Tag() {
        let content = "<password_sha256_hex>abcdef1234567890</password_sha256_hex>"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .xmlCredential })
    }

    func testDetectsXMLSecretAccessKeyTag() {
        let content = "<secret_access_key>wJalrXUtnFEMI</secret_access_key>"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .xmlCredential })
    }

    func testDetectsXMLUserTag() {
        let content = "<user>admin</user>"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .xmlUsername })
    }

    func testDetectsXMLHostTag() {
        let content = "<host>db-primary.internal.corp.net</host>"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .xmlHostname })
    }

    func testDetectsXMLHostnameTag() {
        let content = "<hostname>replica-02.dc1.internal</hostname>"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .xmlHostname })
    }

    func testDetectsXMLInterserverHttpHostTag() {
        let content = "<interserver_http_host>ch-node3.corp.net</interserver_http_host>"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .xmlHostname })
    }

    func testXMLCredentialSeverityIsCritical() {
        XCTAssertEqual(SensitiveDataType.xmlCredential.severity, .critical)
    }

    func testXMLUsernameSeverityIsHigh() {
        XCTAssertEqual(SensitiveDataType.xmlUsername.severity, .high)
    }

    func testXMLHostnameSeverityIsMedium() {
        XCTAssertEqual(SensitiveDataType.xmlHostname.severity, .medium)
    }

    // MARK: - XML Format-Aware Scanning

    func testXMLFormatAwareScanningCatchesEmbeddedSecrets() {
        let content = [
            "<access_key_id>AKIA", "IOSFODNN7EXAMPLE</access_key_id>"
        ].joined()
        let matches = DirectoryScanner.scanFileContent(
            content: content, ext: "xml",
            relativePath: "config.xml", config: config
        )
        // Should catch AWS key via parser extraction
        XCTAssertTrue(matches.contains { $0.type == .awsKey })
    }

    func testXMLFormatAwareScanningCatchesPasswordTags() {
        let content = "<password>plaintext_pass</password>"
        let matches = DirectoryScanner.scanFileContent(
            content: content, ext: "xml",
            relativePath: "users.xml", config: config
        )
        // Raw XML credential rule should fire
        XCTAssertTrue(matches.contains { $0.type == .xmlCredential })
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

    // MARK: - Safe Hosts (Badge and CI Services)

    func testIgnoresBadgeServiceHosts() {
        let badgeHosts = [
            "img.shields.io",
            "badge.fury.io",
            "codecov.io",
            "coveralls.io"
        ]
        for host in badgeHosts {
            let content = "badge: https://\(host)/some/badge.svg"
            let matches = DetectionRules.scan(content, config: config)
            let hostMatches = matches.filter { $0.type == .hostname }
            XCTAssertEqual(hostMatches.count, 0, "\(host) should be in safeHosts")
        }
    }

    func testIgnoresPackageRegistryHosts() {
        let registryHosts = [
            "crates.io",
            "rubygems.org",
            "pkg.go.dev"
        ]
        for host in registryHosts {
            let content = "install from \(host)"
            let matches = DetectionRules.scan(content, config: config)
            let hostMatches = matches.filter { $0.type == .hostname }
            XCTAssertEqual(hostMatches.count, 0, "\(host) should be in safeHosts")
        }
    }

    // MARK: - Configurable Safe/Sensitive Hosts

    func testDefaultConfigBuiltInSafeHostsStillWork() {
        let content = "Visit github.com for source"
        let matches = DetectionRules.scan(content, config: config)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 0, "built-in safeHost should still be excluded")
    }

    func testUserSafeHostNotDetected() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.safeHosts = ["my-safe.internal.com"]
        let content = "Connect to my-safe.internal.com"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 0, "user safeHost should not be detected")
    }

    func testSensitiveHostDetectedEvenIfBuiltInSafe() {
        // img.shields.io is a built-in safe host and matches the 3-segment FQDN regex
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveHosts = ["img.shields.io"]
        let content = "badge at img.shields.io/badge"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 1, "sensitiveHost should override built-in safeHost")
    }

    func testSensitiveHostWinsOverUserSafeHost() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.safeHosts = ["overlap.corp.net"]
        customConfig.sensitiveHosts = ["overlap.corp.net"]
        let content = "Connect to overlap.corp.net"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 1, "sensitiveHost should win over user safeHost")
    }

    func testHostConfigCaseInsensitive() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.safeHosts = ["MY-SAFE.INTERNAL.COM"]
        let content = "Connect to my-safe.internal.com"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 0, "safeHosts lookup should be case insensitive")
    }

    func testSensitiveHostCaseInsensitive() {
        // cdn.jsdelivr.net is a built-in safe host and matches the 3-segment FQDN regex
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveHosts = ["CDN.JSDELIVR.NET"]
        let content = "load from cdn.jsdelivr.net/npm"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 1, "sensitiveHosts lookup should be case insensitive")
    }

    // MARK: - Suffix Matching for Host Lists

    func testSafeHostSuffixSuppressesSubdomain() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.safeHosts = [".company.com"]
        let content = "Connect to db.company.com"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 0, "suffix .company.com should suppress db.company.com")
    }

    func testSafeHostSuffixDoesNotSuppressExactDomain() {
        // "company.com" is only 2 segments — won't match the FQDN regex anyway
        // Use a 3-segment domain to test suffix behavior
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.safeHosts = [".corp.net"]
        let content = "Connect to corp.net.example.org"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        // corp.net.example.org does NOT end with ".corp.net" — should still be detected
        XCTAssertGreaterThanOrEqual(hostMatches.count, 1)
    }

    func testSensitiveHostSuffixFlagsSubdomain() {
        // img.shields.io is built-in safe, but .shields.io suffix in sensitiveHosts should override
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveHosts = [".shields.io"]
        let content = "badge at img.shields.io/badge"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 1, "sensitiveHost suffix should override built-in safe")
    }

    func testSensitiveHostSuffixWinsOverSafeHostSuffix() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.safeHosts = [".corp.net"]
        customConfig.sensitiveHosts = [".corp.net"]
        let content = "Connect to admin.corp.net"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 1, "sensitiveHost suffix should win over safeHost suffix")
    }

    // MARK: - 2-Segment Hostname Detection (WO-50)

    func testTwoSegmentHostDetectedViaSensitiveHosts() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveHosts = [".local"]
        let content = "Connect to nas.local for backups"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 1, ".local suffix should catch 2-segment nas.local")
        XCTAssertEqual(hostMatches.first?.value, "nas.local")
    }

    func testTwoSegmentHostNotDetectedWithoutSensitiveHosts() {
        let content = "Connect to nas.local for backups"
        let matches = DetectionRules.scan(content, config: config)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 0, "2-segment hosts should not be detected by default")
    }

    func testTwoSegmentHostExactMatch() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveHosts = ["printer.lan"]
        let content = "Print to printer.lan"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 1, "exact 2-segment sensitiveHost should be detected")
    }

    func testTwoSegmentHostMultipleDepths() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveHosts = [".local"]
        let content = "hosts: nas.local and db.staging.local"
        let matches = DetectionRules.scan(content, config: customConfig)
        let hostMatches = matches.filter { $0.type == .hostname }
        XCTAssertEqual(hostMatches.count, 2, ".local should match both 2-segment and 3-segment hosts")
    }

    // MARK: - Sensitive IP Prefixes (WO-51)

    func testSensitiveIPPrefixOverridesExclude() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveIPPrefixes = ["8.8."]
        let content = "dns at 8.8.8.8"
        let matches = DetectionRules.scan(content, config: customConfig)
        let ipMatches = matches.filter { $0.type == .ipAddress }
        XCTAssertEqual(ipMatches.count, 1, "sensitiveIPPrefixes should override built-in exclude for 8.8.8.8")
    }

    func testSensitiveIPPrefixMatchesRange() {
        var customConfig = PastewatchConfig.defaultConfig
        customConfig.sensitiveIPPrefixes = ["172.16."]
        let content = "db at 172.16.0.5 and dns at 8.8.8.8"
        let matches = DetectionRules.scan(content, config: customConfig)
        let ipMatches = matches.filter { $0.type == .ipAddress }
        // 172.16.0.5 detected (matches prefix), 8.8.8.8 excluded (built-in exclude, no matching prefix)
        XCTAssertEqual(ipMatches.count, 1, "only 172.16.* should be detected")
        XCTAssertEqual(ipMatches.first?.value, "172.16.0.5")
    }

    func testSensitiveIPPrefixEmpty() {
        // Default config — no sensitive prefixes, normal behavior
        let content = "server at 8.8.8.8"
        let matches = DetectionRules.scan(content, config: config)
        let ipMatches = matches.filter { $0.type == .ipAddress }
        XCTAssertEqual(ipMatches.count, 0, "8.8.8.8 should be excluded by default")
    }

    // MARK: - Workledger Key Detection

    func testDetectsWorkledgerKey() {
        let key = "wl_sk_" + String(repeating: "A", count: 44)
        let content = "WORKLEDGER_API_KEY=\(key)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .workledgerKey },
                      "Should detect workledger API key with wl_sk_ prefix")
    }

    func testWorkledgerKeyTooShort() {
        let key = "wl_sk_" + String(repeating: "A", count: 10)
        let content = "key=\(key)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertFalse(matches.contains { $0.type == .workledgerKey },
                       "Short wl_sk_ value should not match")
    }

    func testWorkledgerKeyInBearerHeader() {
        let key = "wl_sk_" + String(repeating: "B", count: 44)
        let content = "Authorization: Bearer \(key)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .workledgerKey },
                      "Should detect workledger key in Bearer header")
    }

    func testWorkledgerKey43Chars() {
        // Real workledger keygen produces 43-char base64url keys (32 bytes)
        let content = "wl_sk_FHa8DNJ0OKoxvc8Ck9O-A5EZ-2dkAKygE-MkV0gmXFM"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .workledgerKey },
                      "Should detect 43-char workledger key (real format)")
    }

    func testWorkledgerKeyStandalone() {
        // Standalone key with no KEY= context
        let key = "wl_sk_" + String(repeating: "X", count: 43)
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertTrue(matches.contains { $0.type == .workledgerKey },
                      "Should detect standalone wl_sk_ key without context")
    }

    // MARK: - Protected Paths

    func testIsPathProtectedDefaultOpenClaw() {
        let config = PastewatchConfig.defaultConfig
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        XCTAssertTrue(config.isPathProtected(home + "/.openclaw/workledger.key"))
        XCTAssertTrue(config.isPathProtected(home + "/.openclaw/config.json"))
        XCTAssertFalse(config.isPathProtected(home + "/.config/other.json"))
        XCTAssertFalse(config.isPathProtected("/tmp/safe.txt"))
    }

    func testIsPathProtectedTildeExpansion() {
        let config = PastewatchConfig.defaultConfig
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        // Method receives absolute paths from guard commands
        XCTAssertTrue(config.isPathProtected(home + "/.openclaw/workledger.key"))
    }

    func testIsPathProtectedCustomPaths() {
        let config = PastewatchConfig(
            enabled: true,
            enabledTypes: [],
            showNotifications: false,
            soundEnabled: false,
            protectedPaths: ["~/.openclaw", "~/.secrets"]
        )
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        XCTAssertTrue(config.isPathProtected(home + "/.openclaw/key"))
        XCTAssertTrue(config.isPathProtected(home + "/.secrets/token"))
        XCTAssertFalse(config.isPathProtected(home + "/.config/safe"))
    }

    // MARK: - ObstaLabs License Key Detection

    func testDetectsObstalabsKey() {
        // Real format: ol_{base64url payload}.{base64url Ed25519 sig}
        let payload = String(repeating: "a", count: 80)
        let sig = String(repeating: "B", count: 86)
        let key = "ol_\(payload).\(sig)"
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertTrue(matches.contains { $0.type == .obstalabsKey },
                      "Should detect ObstaLabs license key with ol_ prefix")
    }

    func testDetectsObstalabsKeyInEnvContext() {
        let payload = String(repeating: "x", count: 60)
        let sig = String(repeating: "Y", count: 86)
        let content = "OL_LICENSE_KEY=ol_\(payload).\(sig)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .obstalabsKey },
                      "Should detect ObstaLabs key in env var context")
    }

    func testDetectsObstalabsKeyMinimalLength() {
        // Minimum: 20 chars payload + dot + 40 chars sig
        let key = "ol_" + String(repeating: "a", count: 20) + "." + String(repeating: "B", count: 40)
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertTrue(matches.contains { $0.type == .obstalabsKey },
                      "Should detect ObstaLabs key at minimum length threshold")
    }

    func testObstalabsKeyPayloadTooShort() {
        let key = "ol_" + String(repeating: "a", count: 5) + "." + String(repeating: "B", count: 86)
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertFalse(matches.contains { $0.type == .obstalabsKey },
                       "Payload shorter than 20 chars should not match")
    }

    func testObstalabsKeySigTooShort() {
        let key = "ol_" + String(repeating: "a", count: 80) + "." + String(repeating: "B", count: 10)
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertFalse(matches.contains { $0.type == .obstalabsKey },
                       "Signature shorter than 40 chars should not match")
    }

    func testObstalabsKeyNoDot() {
        let key = "ol_" + String(repeating: "a", count: 120)
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertFalse(matches.contains { $0.type == .obstalabsKey },
                       "ol_ key without dot separator should not match")
    }

    func testObstalabsKeySeverityIsCritical() {
        XCTAssertEqual(SensitiveDataType.obstalabsKey.severity, .critical)
    }

    // MARK: - Resend API Key Detection

    func testDetectsResendKey() {
        let key = "re_" + String(repeating: "A", count: 32)
        let content = "RESEND_API_KEY=\(key)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .resendKey },
                      "Should detect Resend API key with re_ prefix")
    }

    func testDetectsResendKeyStandalone() {
        let key = "re_" + String(repeating: "B", count: 40)
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertTrue(matches.contains { $0.type == .resendKey },
                      "Should detect standalone Resend API key")
    }

    func testDetectsResendKeyInConfig() {
        let key = "re_" + String(repeating: "C", count: 40)
        let content = "resend_key: \(key)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .resendKey },
                      "Should detect Resend key in config context")
    }

    func testResendKeyTooShort() {
        let key = "re_" + String(repeating: "A", count: 10)
        let matches = DetectionRules.scan(key, config: config)
        XCTAssertFalse(matches.contains { $0.type == .resendKey },
                       "Resend key shorter than 24 chars should not match")
    }

    func testResendKeySeverityIsCritical() {
        XCTAssertEqual(SensitiveDataType.resendKey.severity, .critical)
    }

    // MARK: - Stripe Webhook Secret Detection

    func testDetectsStripeWebhookSecret() {
        let secret = "whsec_" + String(repeating: "A", count: 32)
        let content = "STRIPE_WEBHOOK_SECRET=\(secret)"
        let matches = DetectionRules.scan(content, config: config)
        XCTAssertTrue(matches.contains { $0.type == .genericApiKey },
                      "Should detect Stripe webhook secret with whsec_ prefix")
    }

    func testDetectsStripeWebhookSecretStandalone() {
        let secret = "whsec_" + String(repeating: "B", count: 40)
        let matches = DetectionRules.scan(secret, config: config)
        XCTAssertTrue(matches.contains { $0.type == .genericApiKey },
                      "Should detect standalone whsec_ secret")
    }

    func testStripeWebhookSecretTooShort() {
        let secret = "whsec_" + String(repeating: "A", count: 10)
        let matches = DetectionRules.scan(secret, config: config)
        // Short value — should not be detected as genericApiKey via whsec_ rule
        XCTAssertFalse(matches.contains { $0.type == .genericApiKey && $0.value.hasPrefix("whsec_") },
                       "whsec_ value shorter than 24 chars should not match")
    }

    // WO-462/WO-481/WO-482/WO-483/WO-485: standalone provider tokens must be
    // recognized from their documented intrinsic format, without keyword context.
    func testDetectsStandaloneProviderTokens() {
        let slackStem = String(bytes: [120, 111, 120], encoding: .utf8) ?? ""
        let fixtures: [(SensitiveDataType, String)] = [
            (.vaultToken, "hvs." + String(repeating: "A1", count: 12)),
            (.vaultToken, "hvb." + String(repeating: "B2", count: 12)),
            (.vaultToken, "hvr." + String(repeating: "C3", count: 12)),
            (.vaultToken, "s.iyNUgdDrn8sBHtdb9Vjfhk3n"),
            (.vaultToken, "b." + String(repeating: "c3", count: 12)),
            (.vaultToken, "r." + String(repeating: "d4", count: 12)),
            (.slackToken, slackStem + "b-1234567890-" + String(repeating: "Ab", count: 12)),
            (.slackToken, slackStem + "p-1234567890-" + String(repeating: "Bc", count: 12)),
            (.slackToken, "xapp-1-A1234567890-" + String(repeating: "Cd", count: 12)),
            (.slackToken, "xwfp-" + String(repeating: "Ef", count: 12)),
            (.slackToken, slackStem + "e." + slackStem + "p-1-" + String(repeating: "Gh", count: 12)),
            (.slackToken, "xoxe-1-" + String(repeating: "Ij", count: 12)),
            (.googleApiKey, "AIza" + String(repeating: "K", count: 35)),
            (.dockerAccessToken, "dckr_pat_" + String(repeating: "L", count: 15)),
            (.dockerAccessToken, "dckr_oat_" + String(repeating: "N", count: 15)),
            (.githubToken, "github_pat_" + String(repeating: "Pq", count: 20)),
            (.githubToken, "ghs_12345_" + jwtFixture())
        ]

        for (type, fixture) in fixtures {
            let matches = DetectionRules.scan(fixture, config: config)
            XCTAssertTrue(
                matches.contains { $0.type == type && $0.value == fixture && $0.mutationSafe },
                "expected complete intrinsic match for \(type.rawValue)"
            )
        }
    }

    func testProviderTokenNearMissesDoNotMatch() {
        let slackStem = String(bytes: [120, 111, 120], encoding: .utf8) ?? ""
        let nearMisses = [
            "hvs.short",
            "prefixhvb." + String(repeating: "A", count: 24),
            "s.formatMessageWithAllArgumentsProvidedHere",
            "r.status_code_was_definitely_not_two_hundred_here",
            "b.filesWithVeryLongDescriptiveNamesInAModuleHere",
            "s." + String(repeating: "A", count: 25),
            "b." + String(repeating: "B", count: 23),
            "xoxa-" + String(repeating: "B", count: 24),
            slackStem + "b-short",
            slackStem + "e." + slackStem + "a-1-" + String(repeating: "C", count: 24),
            slackStem + "e." + slackStem + "p-" + String(repeating: "D", count: 24),
            slackStem + "e-not-a-version-" + String(repeating: "E", count: 24),
            "AIza" + String(repeating: "F", count: 34),
            "AIza" + String(repeating: "G", count: 36),
            "AIza" + String(repeating: "H", count: 17) + "!" + String(repeating: "I", count: 17),
            "prefixAIza" + String(repeating: "J", count: 35),
            "dckr_pat_short",
            "dckr_oat_" + String(repeating: "K", count: 14),
            "dckr_pat_" + String(repeating: "L", count: 7) + "!" + String(repeating: "L", count: 8),
            "prefixdckr_pat_" + String(repeating: "M", count: 15),
            "github_pat_short",
            "github_pat_" + String(repeating: "N", count: 19),
            "github_pat_" + String(repeating: "O", count: 10) + "-" + String(repeating: "O", count: 10),
            "prefixgithub_pat_" + String(repeating: "P", count: 20),
            "ghs_not-an-app-id_" + jwtFixture(),
            "ghs_12345_not-a-jwt"
        ]

        for value in nearMisses {
            let matches = DetectionRules.scan(value, config: config)
            XCTAssertFalse(matches.contains { [.vaultToken, .slackToken, .googleApiKey,
                .dockerAccessToken, .githubToken].contains($0.type) }, "unexpected match for \(value.prefix(16))")
        }
    }

    // WO-478: the match must contain the full private payload, not only its marker.
    func testSSHPrivateKeyMatchesCompleteBoundedPEMBlocks() {
        let first = pemFixture(label: "OPENSSH PRIVATE KEY", payload: String(repeating: "QUJD", count: 12), newline: "\n")
        let second = pemFixture(label: "RSA PRIVATE KEY", payload: String(repeating: "REVG", count: 12), newline: "\r\n")
        let content = first + "\npublic text\n" + second
        let matches = DetectionRules.scan(content, config: config).filter { $0.type == .sshPrivateKey }

        XCTAssertEqual(matches.map(\.value), [first, second])
        let redacted = Obfuscator.obfuscate(content, matches: matches)
        XCTAssertFalse(redacted.contains("PRIVATE KEY-----"))
        XCTAssertFalse(redacted.contains("QUJD"))
        XCTAssertFalse(redacted.contains("REVG"))
    }

    // WO-478: malformed recognized private-key blocks are advisory findings, not
    // successful secret containment matches.
    func testSSHPrivateKeyReportsMalformedBlocksWithoutAuthorizingMutation() {
        let incomplete = "-----BEGIN OPENSSH PRIVATE " + "KEY-----\n" + String(repeating: "QUJD", count: 12)
        let mismatched = incomplete + "\n-----END RSA PRIVATE KEY-----"
        let nested = incomplete + "\n" + pemFixture(
            label: "RSA PRIVATE KEY", payload: String(repeating: "REVG", count: 12), newline: "\n"
        )
        let oversized = pemFixture(
            label: "PRIVATE KEY", payload: String(repeating: "A", count: 262_145), newline: "\n"
        )

        for value in [incomplete, mismatched, nested, oversized] {
            let matches = DetectionRules.scan(value, config: config)
            let privateKeyMatches = matches.filter { $0.type == .sshPrivateKey }
            XCTAssertFalse(privateKeyMatches.isEmpty)
            XCTAssertTrue(privateKeyMatches.allSatisfy { $0.advisory == .malformedPrivateKey })
            XCTAssertTrue(privateKeyMatches.allSatisfy { !$0.mutationSafe })
            XCTAssertEqual(Obfuscator.obfuscate(value, matches: matches), value)
        }

        for value in [
            "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"
        ] {
            XCTAssertFalse(DetectionRules.scan(value, config: config).contains { $0.advisory != nil })
        }
    }

    // WO-479: only secret-bearing fields in a structurally identified service-account
    // object are authorized; the type marker itself is context, not a secret.
    func testGCPServiceAccountMatchesPrivateFieldsAndPreservesJSON() throws {
        let key = pemFixture(label: "PRIVATE KEY", payload: String(repeating: "R0NQ", count: 12), newline: "\n")
        let keyID = String(repeating: "a1", count: 20)
        let object: [String: Any] = [
            "wrapper": [
                "type": "service_account",
                "private_key_id": keyID,
                "private_key": key,
                "unknown": true
            ]
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let content = try XCTUnwrap(String(data: data, encoding: .utf8))
        let matches = DetectionRules.scan(content, config: config).filter { $0.type == .gcpServiceAccount }

        XCTAssertEqual(Set(matches.map(\.value)), Set([keyID, try jsonEscapedStringContent(key)]))
        let redacted = Obfuscator.obfuscate(content, matches: matches)
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(redacted.utf8)))
        XCTAssertFalse(redacted.contains(keyID))
        XCTAssertFalse(redacted.contains("R0NQ"))
        XCTAssertTrue(redacted.contains("service_account"))
    }

    func testGCPMarkerAloneAndBenignPrivateFieldsDoNotAuthorizeMutation() throws {
        let benign: [String: Any] = [
            "type": "user",
            "private_key_id": String(repeating: "a1", count: 20),
            "private_key": "not a service account key"
        ]
        let data = try JSONSerialization.data(withJSONObject: benign, options: [.sortedKeys])
        let content = try XCTUnwrap(String(data: data, encoding: .utf8))

        XCTAssertFalse(DetectionRules.scan(content, config: config).contains { $0.type == .gcpServiceAccount })
        XCTAssertFalse(DetectionRules.scan(#"{"type":"service_account"}"#, config: config)
            .contains { $0.type == .gcpServiceAccount })
    }

    // WO-479: authorization belongs to an exact object path/range, never to an
    // equal value elsewhere in the JSON document.
    func testGCPServiceAccountRangesDoNotAuthorizeEqualSiblingValues() throws {
        let key = "gcp-private-material-\r\n" + String(repeating: "R0NQ", count: 12)
        let keyID = String(repeating: "b2", count: 20)
        let object: [String: Any] = [
            "service": [
                "private_key": key,
                "nested": ["private_key": key, "private_key_id": keyID],
                "type": "service_account",
                "private_key_id": keyID
            ],
            "benign": ["type": "user", "private_key": key, "private_key_id": keyID],
            "services": [["private_key_id": keyID, "type": "service_account", "private_key": key]]
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let content = try XCTUnwrap(String(data: data, encoding: .utf8))
        let matches = DetectionRules.scan(content, config: config).filter { $0.type == .gcpServiceAccount }

        XCTAssertEqual(matches.count, 4)
        let redacted = Obfuscator.obfuscate(content, matches: matches)
        let parsed = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(redacted.utf8)) as? [String: Any]
        )
        let service = try XCTUnwrap(parsed["service"] as? [String: Any])
        let nested = try XCTUnwrap(service["nested"] as? [String: Any])
        let benign = try XCTUnwrap(parsed["benign"] as? [String: Any])
        let services = try XCTUnwrap(parsed["services"] as? [[String: Any]])

        XCTAssertNotEqual(service["private_key"] as? String, key)
        XCTAssertNotEqual(service["private_key_id"] as? String, keyID)
        XCTAssertEqual(nested["private_key"] as? String, key)
        XCTAssertEqual(nested["private_key_id"] as? String, keyID)
        XCTAssertEqual(benign["private_key"] as? String, key)
        XCTAssertEqual(benign["private_key_id"] as? String, keyID)
        XCTAssertNotEqual(services.first?["private_key"] as? String, key)
        XCTAssertNotEqual(services.first?["private_key_id"] as? String, keyID)
    }

    private func pemFixture(label: String, payload: String, newline: String) -> String {
        "-----BEGIN \(label)-----\(newline)\(payload)\(newline)-----END \(label)-----"
    }

    private func jsonEscapedStringContent(_ value: String) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: [value])
        let encoded = try XCTUnwrap(String(data: data, encoding: .utf8))
        return String(encoded.dropFirst(2).dropLast(2))
    }

    private func jwtFixture() -> String {
        "eyJ" + String(repeating: "A", count: 12) + ".eyJ" + String(repeating: "B", count: 12) + "." + String(repeating: "C", count: 20)
    }
}
