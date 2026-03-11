import XCTest
@testable import PastewatchCore

final class XMLValueParserTests: XCTestCase {

    let parser = XMLValueParser()

    // MARK: - Basic Tag Extraction

    func testExtractsPasswordTag() {
        let xml = "<password>secret123</password>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.value, "secret123")
        XCTAssertEqual(values.first?.key, "password")
        XCTAssertEqual(values.first?.line, 1)
    }

    func testExtractsPasswordSHA256Tag() {
        let xml = "<password_sha256_hex>e3b0c44298fc1c149afbf4c8996fb924</password_sha256_hex>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "password_sha256_hex")
    }

    func testExtractsHostTag() {
        let xml = "<host>db-primary.internal.corp.net</host>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.value, "db-primary.internal.corp.net")
        XCTAssertEqual(values.first?.key, "host")
    }

    func testExtractsUserTag() {
        let xml = "<user>admin</user>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.value, "admin")
    }

    func testExtractsAccessKeyTag() {
        let content = [
            "<access_key_id>AKIA", "IOSFODNN7EXAMPLE</access_key_id>"
        ].joined()
        let values = parser.parseValues(from: content)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "access_key_id")
    }

    func testExtractsSecretAccessKeyTag() {
        let xml = "<secret_access_key>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</secret_access_key>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "secret_access_key")
    }

    // MARK: - Multiline ClickHouse Config

    func testClickHouseUsersConfig() {
        let xml = """
        <?xml version="1.0"?>
        <clickhouse>
            <users>
                <default>
                    <password>ch_secret_pass</password>
                    <quota_key>default_quota</quota_key>
                </default>
                <readonly>
                    <password_sha256_hex>abcdef1234567890</password_sha256_hex>
                </readonly>
            </users>
        </clickhouse>
        """
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 3)
        XCTAssertTrue(values.contains { $0.key == "password" && $0.value == "ch_secret_pass" })
        XCTAssertTrue(values.contains { $0.key == "quota_key" })
        XCTAssertTrue(values.contains { $0.key == "password_sha256_hex" })
    }

    func testClickHouseRemoteServersConfig() {
        let xml = """
        <remote_servers>
            <cluster1>
                <shard>
                    <replica>
                        <host>ch-node1.internal.corp.net</host>
                        <user>replicator</user>
                        <password>repl_pass_123</password>
                    </replica>
                </shard>
            </cluster1>
        </remote_servers>
        """
        let values = parser.parseValues(from: xml)
        XCTAssertTrue(values.contains { $0.key == "host" && $0.value == "ch-node1.internal.corp.net" })
        XCTAssertTrue(values.contains { $0.key == "user" && $0.value == "replicator" })
        XCTAssertTrue(values.contains { $0.key == "password" && $0.value == "repl_pass_123" })
    }

    // MARK: - Tag Attributes

    func testTagWithAttributes() {
        let xml = #"<password replace="true">new_secret</password>"#
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.value, "new_secret")
    }

    // MARK: - CDATA

    func testStripsCDATA() {
        let xml = "<password><![CDATA[complex>pass<word]]></password>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.value, "complex>pass<word")
    }

    // MARK: - Filtering

    func testSkipsNonSensitiveTags() {
        let xml = """
        <clickhouse>
            <max_memory_usage>10000000000</max_memory_usage>
            <listen_host>0.0.0.0</listen_host>
            <password>real_secret</password>
        </clickhouse>
        """
        let values = parser.parseValues(from: xml)
        // Only password should be extracted (listen_host is not in default sensitive tags,
        // max_memory_usage is not sensitive)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "password")
    }

    func testSkipsXMLComments() {
        let xml = """
        <!-- <password>commented_out</password> -->
        <password>real_value</password>
        """
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.value, "real_value")
    }

    func testSkipsProcessingInstructions() {
        let xml = """
        <?xml version="1.0"?>
        <password>value</password>
        """
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
    }

    func testSkipsEmptyTags() {
        let xml = "<password></password>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 0)
    }

    // MARK: - Line Numbers

    func testCorrectLineNumbers() {
        let xml = """
        <config>
            <host>db.corp.net</host>
            <port>9000</port>
            <password>secret</password>
        </config>
        """
        let values = parser.parseValues(from: xml)
        let hostValue = values.first { $0.key == "host" }
        let passValue = values.first { $0.key == "password" }
        XCTAssertEqual(hostValue?.line, 2)
        XCTAssertEqual(passValue?.line, 4)
    }

    // MARK: - Custom Tags

    func testCustomSensitiveTags() {
        let customParser = XMLValueParser(sensitiveTags: ["custom_secret", "api_key"])
        let xml = """
        <custom_secret>my_value</custom_secret>
        <password>ignored</password>
        <api_key>key123</api_key>
        """
        let values = customParser.parseValues(from: xml)
        XCTAssertEqual(values.count, 2)
        XCTAssertTrue(values.contains { $0.key == "custom_secret" })
        XCTAssertTrue(values.contains { $0.key == "api_key" })
        XCTAssertFalse(values.contains { $0.key == "password" })
    }

    // MARK: - Connection Strings

    func testExtractsConnectionStringTag() {
        let connStr = ["postgres://admin:pass", "@db:5432/prod"].joined()
        let xml = "<connection_string>\(connStr)</connection_string>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "connection_string")
    }

    func testExtractsURLTag() {
        let xml = "<url>https://s3.amazonaws.com/bucket/key</url>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "url")
    }

    // MARK: - Hostname Tag

    func testExtractsHostnameTag() {
        let xml = "<hostname>replica-02.dc1.internal</hostname>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "hostname")
    }

    func testExtractsInterserverHttpHostTag() {
        let xml = "<interserver_http_host>ch-node3.internal.corp.net</interserver_http_host>"
        let values = parser.parseValues(from: xml)
        XCTAssertEqual(values.count, 1)
        XCTAssertEqual(values.first?.key, "interserver_http_host")
    }

    // MARK: - Parser Registration

    func testXMLParserRegistered() {
        XCTAssertNotNil(parserForExtension("xml"))
    }

    func testXMLParserWithCustomConfig() {
        var config = PastewatchConfig.defaultConfig
        config.xmlSensitiveTags = ["custom_tag"]
        let parser = parserForExtension("xml", config: config)
        XCTAssertNotNil(parser)

        // Should parse both default and custom tags
        let xml = """
        <password>secret</password>
        <custom_tag>custom_value</custom_tag>
        """
        let values = parser?.parseValues(from: xml) ?? []
        XCTAssertEqual(values.count, 2)
    }
}
