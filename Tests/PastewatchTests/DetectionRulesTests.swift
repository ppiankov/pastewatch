import XCTest
@testable import Pastewatch

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
