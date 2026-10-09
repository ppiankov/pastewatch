import Foundation
import XCTest
@testable import PastewatchCore
@testable import PastewatchCLI

// WO-639: keep whole-match policy contracts independent from password-only mutation.
final class DSNPasswordEvidenceTests: XCTestCase {
    // WO-642@v2: reserved password bytes retain intrinsic evidence across the real decision paths.
    func testRawDSNPasswordDelimitersAcrossGuardCheckAndMCP() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            let config = fixtureConfig()
            try JSONEncoder().encode(config).write(to: root.appendingPathComponent(".pastewatch.json"))
            let explanation = ConfigExplanation(
                currentDirectory: root.path,
                systemConfigPath: root.appendingPathComponent("absent-system.json").path,
                userConfigPath: root.appendingPathComponent("absent-user.json").path
            )
            let session = try MCPProtocolTests.LiveMCPSession(
                executableURL: cliURL(), maximumLineBytes: 65_536, config: config
            )
            defer { session.close() }
            for delimiter in ["#", "/", "?"] {
                let password = "Q7" + delimiter + fixturePassword()
                let content = fixtureConnection(password) + "\n"
                let path = session.directory.appendingPathComponent("reserved.md")
                try Data(content.utf8).write(to: path)
                let matches = DetectionRules.scan(content, config: config)
                let decision = GuardDecision.evaluate(
                    matches: matches, content: content, config: config, contentTrust: .trustedFile,
                    minimumSeverity: .high, filePath: path.path
                )
                XCTAssertEqual(decision.actionableMatches.count, 1)
                let verdict = try ValueVerdict(content: content, filePath: path.path, explanation: explanation)
                XCTAssertEqual(verdict.findings.count, 1)
                XCTAssertTrue(verdict.findings.first?.mutationAuthorized == true)
                XCTAssertTrue(verdict.findings.first?.mcp == "placeholder, restored on write")
                let payload = try mcpPayload(session, name: "pastewatch_read_file", arguments: ["path": .string(path.path)])
                let entries = try XCTUnwrap(payload["redactions"] as? [[String: Any]])
                XCTAssertEqual(entries.count, 1)
                guard let marker = entries.first?["placeholder"] as? String else { continue }
                let redacted = try XCTUnwrap(payload["content"] as? String)
                XCTAssertTrue(redacted == content.replacingOccurrences(of: password, with: marker))
                _ = try mcpPayload(session, name: "pastewatch_write_file", arguments: [
                    "path": .string(path.path), "content": .string(redacted)
                ])
                XCTAssertTrue(try Data(contentsOf: path) == Data(content.utf8))
            }
        }
    }

    // WO-642@v2: a query parameter's final at-sign is not the userinfo boundary.
    func testTerminalQueryAtSignsDoNotStealPasswordEvidence() throws {
        let password = fixturePassword()
        let query = "?owner=" + ["observer", "@", "mail.example"].joined()
        let content = fixtureConnection(password) + query
        let match = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
        let span = DetectionRules.dsnUserinfoPasswordRange(in: content, connectionRange: match.range)
        XCTAssertTrue(span.map { String(content[$0]) == password } == true)
        let hostOnly = ["post", "gres", "://", "db:5432/prod", query].joined()
        let advisory = try XCTUnwrap(DetectionRules.scan(hostOnly, config: fixtureConfig()).first)
        XCTAssertNil(DetectionRules.dsnUserinfoPasswordRange(in: hostOnly, connectionRange: advisory.range))
        XCTAssertTrue(advisory.mutationAuthorizationSources.isEmpty)
    }

    // WO-642@v2: the host grammar must prove a nonempty authority after the userinfo delimiter.
    func testInvalidDSNHostSuffixDoesNotAuthorizePassword() throws {
        for suffix in ["", ":", "[not-an-ipv6-address]"] {
            let content = ["post", "gres", "://", "app:Q7/", fixturePassword(), "@", suffix].joined()
            let span = DetectionRules.dsnUserinfoPasswordRange(
                in: content, connectionRange: content.startIndex..<content.endIndex
            )
            XCTAssertNil(span)
        }
    }

    // WO-642@v2: a valid authority takes precedence over at-signs in later URL components.
    func testValidAuthoritiesKeepPathQueryAndFragmentAtSignsAdvisory() throws {
        for authority in ["host:5432", "host", "127.0.0.1:5432", "[::1]:5432"] {
            for suffix in ["/db?x=a@b", "/db?user=a@b.com", "/a@b.com", "#a@b.com"] {
                let content = ["post", "gres", "://", authority, suffix].joined()
                let match = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
                XCTAssertNil(DetectionRules.dsnUserinfoPasswordRange(in: content, connectionRange: match.range))
                XCTAssertTrue(match.mutationAuthorizationSources.isEmpty)
            }
        }
    }

    // WO-642@v2: numeric password prefixes are intentionally indistinguishable from valid host ports.
    func testNumericPasswordPrefixRemainsAnAcceptedAdvisory() throws {
        for delimiter in ["/", "?", "#"] {
            let content = ["post", "gres", "://", "u:12", delimiter, "x@db"].joined()
            let match = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
            XCTAssertNil(match.mutationSubrange)
            XCTAssertTrue(match.mutationAuthorizationSources.isEmpty)
        }
    }

    // WO-639: raw files keep targeting when the source match gains path metadata.
    func testRealMCPReadWriteRawFilesAcrossUnicodeOffsets() throws {
        try assertMCPFormats(["md", "txt"])
    }

    // WO-639: dotenv value offsets must be rebased past the assignment and optional Unicode prefix.
    func testRealMCPReadWriteDotenvAcrossUnicodeOffsets() throws {
        try assertMCPFormats(["env"])
    }

    // WO-639: JSON decoding and source matching must preserve password-only targeting.
    func testRealMCPReadWriteJSONAcrossUnicodeOffsets() throws {
        try assertMCPFormats(["json"])
    }

    // WO-639: YAML value extraction must not leave parser-local mutation indices in a file match.
    func testRealMCPReadWriteYAMLAcrossUnicodeOffsets() throws {
        try assertMCPFormats(["yaml"])
    }

    // WO-639: documentation examples are part of the tested placeholder contract.
    func testREADMEPlaceholderFormsAndWordsStayInSync() throws {
        let readme = try String(contentsOf: repositoryRoot().appendingPathComponent("README.md"), encoding: .utf8)
        let start = try XCTUnwrap(readme.range(of: "### Documenting credentials\n"))
        let remaining = readme[start.upperBound...]
        let end = try XCTUnwrap(remaining.range(of: "\n## "))
        let section = String(remaining[..<end.lowerBound])
        let examples = section.split(separator: "\n").filter { $0.hasPrefix("| ") && $0.contains("`") }
            .flatMap { $0.split(separator: "`", omittingEmptySubsequences: false).enumerated()
                .filter { $0.offset % 2 == 1 }.map { String($0.element) } }
        XCTAssertEqual(examples.count, 8)
        for example in examples {
            let match = try XCTUnwrap(DetectionRules.scan(fixtureConnection(example), config: fixtureConfig()).first)
            XCTAssertTrue(match.mutationAuthorizationSources.isEmpty)
            XCTAssertNil(match.mutationSubrange)
        }
        let words = try XCTUnwrap(section.split(separator: "\n").first { $0.hasPrefix("Accepted words:") })
        let documentedWords = Set(words.split(separator: "`", omittingEmptySubsequences: false).enumerated()
            .filter { $0.offset % 2 == 1 }.map { String($0.element) })
        XCTAssertEqual(documentedWords.count, 17)
        XCTAssertTrue(documentedWords == DetectionRules.DSNPlaceholderPasswords)
        for word in DetectionRules.DSNPlaceholderPasswords {
            let matches = DetectionRules.scan(fixtureConnection(word), config: fixtureConfig())
            XCTAssertEqual(matches.count, 1)
            XCTAssertTrue(matches.allSatisfy { $0.mutationAuthorizationSources.isEmpty })
        }
        for pattern in DetectionRules.DSNPlaceholderTemplates {
            XCTAssertTrue(examples.contains { example in
                example.range(of: pattern, options: [.regularExpression, .caseInsensitive]) == example.startIndex..<example.endIndex
            }, "each documented template family needs an example")
        }
    }

    // WO-639: common leetspeak passwords are not new exceptions to the closed placeholder vocabulary.
    func testLeetspeakLookalikesRemainSecretEvidence() throws {
        for password in [["pass", "w0rd"].joined(), ["p@ss", "w0rd"].joined()] {
            let content = fixtureConnection(password)
            let matches = DetectionRules.scan(content, config: fixtureConfig())
            let match = try XCTUnwrap(matches.first)
            XCTAssertTrue(match.mutationAuthorizationSources.contains(.intrinsicFormat))
            let decision = GuardDecision.evaluate(
                matches: matches, content: content, config: fixtureConfig(), contentTrust: .trustedFile,
                minimumSeverity: .high, filePath: "guide.md"
            )
            XCTAssertEqual(decision.actionableMatches.count, 1)
        }
    }

    // WO-639: failed source identity verification discards targeting without dropping authorization or restoration.
    func testForcedSourceMismatchFallsBackToWholeConnection() throws {
        let connection = fixtureConnection(fixturePassword())
        let content = "\u{1F511} prefix\n" + connection + "\nsuffix"
        let config = fixtureConfig()
        let match = try XCTUnwrap(DetectionRules.scan(content, config: config).first)
        let wrongSource = content.replacingOccurrences(of: "@db:", with: "@xx:")
        let copied = DirectoryScanner.sourceMatch(
            match, range: match.range, line: match.line, filePath: "guide.md",
            parsedContent: content, source: wrongSource
        )
        XCTAssertNil(copied.mutationSubrange)
        XCTAssertEqual(copied.mutationAuthorizationSources, match.mutationAuthorizationSources)
        let decision = MCPReadDecision.evaluate(
            matches: [copied], content: content, config: config, minimumSeverity: .high, filePath: "guide.md"
        )
        let store = RedactionStore()
        let (redacted, entries) = store.redact(content: content, matches: decision.authorized, filePath: "guide.md")
        let marker = try XCTUnwrap(entries.first?.placeholder)
        XCTAssertTrue(redacted == "\u{1F511} prefix\n" + marker + "\nsuffix")
        XCTAssertTrue(Data(store.resolve(content: redacted, filePath: "guide.md").content.utf8) == Data(content.utf8))
    }

    // WO-672@v1: the guard probe uses fixture-owned project and global tiers.
    // WO-639: the published README must remain readable under explicit Credential and DB Connection policy.
    func testREADMEPassesGuardReadWithOptedInDetectors() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try JSONEncoder().encode(fixtureConfig()).write(to: root.appendingPathComponent(".pastewatch.json"))
            let path = root.appendingPathComponent("README.md")
            try Data(contentsOf: repositoryRoot().appendingPathComponent("README.md")).write(to: path)
            let content = try String(contentsOf: path, encoding: .utf8)
            let matches = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: "md", relativePath: path.path, config: fixtureConfig()
            )
            let decision = GuardDecision.evaluate(
                matches: matches, content: content, config: fixtureConfig(), contentTrust: .trustedFile,
                minimumSeverity: .high, filePath: path.path
            )
            XCTAssertTrue(decision.actionableMatches.isEmpty, decision.actionableMatches.map {
                "\($0.type.rawValue) line=\($0.line) count=1"
            }.joined(separator: ", "))
            let process = Process()
            process.executableURL = cliURL()
            process.arguments = ["guard-read", path.path]
            process.currentDirectoryURL = root
            // WO-672@v1: isolate the child global policy independently of project policy.
            process.environment = TestConfigHelper.subprocessEnvironment(["PW_GUARD": "1"])
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0)
        }
    }

    // WO-672@v1: user-tier whole-value exemptions retain the original DSN comparison contract.
    // WO-639: exact allowlists continue to compare with the entire detected connection.
    func testWholeConnectionAllowlistSuppressesButPasswordAloneDoesNot() throws {
        let password = fixturePassword()
        let connection = fixtureConnection(password)
        for (allowed, expected) in [(connection, 0), (password, 1)] {
            var config = fixtureConfig()
            config.allowedValues = [allowed]
            // WO-672@v1: this control represents an operator-owned exact entry.
            config.allowedValueSources[allowed] = [.user]
            let decision = GuardDecision.evaluate(
                matches: DetectionRules.scan(connection, config: config), content: connection, config: config,
                contentTrust: .trustedFile, minimumSeverity: .high, filePath: "guide.md"
            )
            XCTAssertEqual(decision.actionableMatches.count, expected)
        }
    }

    // WO-672@v1: patterns and inline directives suppress advisory DSNs, never intrinsic passwords.
    // WO-639: anchored patterns retain their whole-DSN comparison semantics.
    func testAllowlistPatternsAndInlineAllowKeepWholeMatchSemantics() {
        let password = fixturePassword()
        let connection = fixtureConnection(password)
        // WO-672@v1: both whole and partial patterns leave intrinsic evidence intact.
        for pattern in [connection, password] {
            var config = fixtureConfig()
            config.allowedPatterns = [NSRegularExpression.escapedPattern(for: pattern)]
            let matches = DetectionRules.scan(connection, config: config)
            // WO-672@v1: pattern-based authority never exempts an intrinsic password.
            XCTAssertEqual(Allowlist.fromConfig(config).filter(matches).count, 1)
            let advisoryConnection = fixtureConnection("pass" + "word")
            config.allowedPatterns = [NSRegularExpression.escapedPattern(for: advisoryConnection)]
            XCTAssertTrue(Allowlist.fromConfig(config).filter(DetectionRules.scan(advisoryConnection, config: config)).isEmpty)
        }
        let content = connection + " # pastewatch:allow\n"
        let config = fixtureConfig()
        let decision = GuardDecision.evaluate(
            matches: DetectionRules.scan(content, config: config), content: content, config: config,
            contentTrust: .trustedFile, minimumSeverity: .high, filePath: "guide.md"
        )
        // WO-672@v1: the same directive still suppresses the advisory-only placeholder form.
        XCTAssertEqual(decision.reportableMatches.count, 1)
        let advisoryContent = fixtureConnection("pass" + "word") + " # pastewatch:allow\n"
        XCTAssertTrue(Allowlist.filterInlineAllow(matches: DetectionRules.scan(advisoryContent, config: config),
                                                 content: advisoryContent).isEmpty)
    }

    // WO-672@v1: project exact entries do not gain the user-tier DSN exemption.
    func testProjectWholeConnectionAllowlistCannotSuppressIntrinsicPassword() {
        let connection = fixtureConnection(fixturePassword())
        var config = fixtureConfig()
        config.allowedValues = [connection]
        config.allowedValueSources[connection] = [.project]
        XCTAssertEqual(GuardDecision.evaluate(matches: DetectionRules.scan(connection, config: config),
                                             content: connection, config: config, contentTrust: .trustedFile,
                                             minimumSeverity: .high, filePath: "guide.md").actionableMatches.count, 1)
    }

    // WO-639: origin/main fingerprints the whole type/value pair, irrespective of mutation evidence.
    func testWholeConnectionBaselineFingerprintIsUnchanged() throws {
        let connection = fixtureConnection(fixturePassword())
        let content = "\u{1F511} prefix\n" + connection + "\n"
        let wholeRange = try XCTUnwrap(content.range(of: connection))
        let legacyMatch = DetectedMatch(type: .dbConnectionString, value: connection, range: wholeRange, line: 2)
        let current = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
        XCTAssertTrue(current.value == connection)
        XCTAssertEqual(current.range, wholeRange)
        XCTAssertEqual(current.line, 2)
        let legacy = BaselineEntry.from(match: legacyMatch, filePath: "guide.md")
        let actual = BaselineEntry.from(match: current, filePath: "guide.md")
        XCTAssertTrue(actual == legacy, "baseline identity must not depend on mutation-span evidence")
        XCTAssertTrue(BaselineFile(entries: [legacy]).filterNew(matches: [current], filePath: "guide.md").isEmpty)
    }

    // WO-639: proxy JSON splicing keeps the connection container and changes only its password.
    func testProxyOutboundReplacesOnlyPasswordAcrossStringPositions() throws {
        let server = ProxyServer(config: fixtureConfig(), quietLog: true)
        for password in [fixturePassword(), "\u{00E9}" + fixturePassword(), "%51" + fixturePassword()] {
            let connection = fixtureConnection(password)
            let content = "\u{1F511} leading text\n" + connection + "\ntrailing text"
            let body = try JSONSerialization.data(withJSONObject: [
                "model": "claude-test", "max_tokens": 1,
                "messages": [["role": "user", "content": content]]
            ])
            let bodyText = try XCTUnwrap(String(data: body, encoding: .utf8))
            let result = server.scanAndRedactBody(bodyText)
            XCTAssertFalse(result.serializationFailed)
            XCTAssertEqual(result.redacted, 1)
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(result.body.utf8)) as? [String: Any])
            let messages = try XCTUnwrap(json["messages"] as? [[String: Any]])
            let actual = try XCTUnwrap(messages.first?["content"] as? String)
            let placeholder = Obfuscator.makePlaceholder(type: .dbConnectionString, number: 1)
            XCTAssertTrue(actual == content.replacingOccurrences(of: password, with: placeholder))
            XCTAssertFalse(actual.contains(password))
        }
    }

    // WO-639: check must associate password mutations with the original whole-DSN finding.
    func testCheckReportsPasswordMutationAsOneWholeConnectionFinding() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { root in
            try JSONEncoder().encode(fixtureConfig()).write(to: root.appendingPathComponent(".pastewatch.json"))
            let explanation = ConfigExplanation(
                currentDirectory: root.path,
                systemConfigPath: root.appendingPathComponent("absent-system.json").path,
                userConfigPath: root.appendingPathComponent("absent-user.json").path
            )
            let report = try ValueVerdict(
                content: fixtureConnection(fixturePassword()),
                filePath: root.appendingPathComponent("guide.md").path, explanation: explanation
            )
            XCTAssertEqual(report.findings.count, 1)
            let finding = try XCTUnwrap(report.findings.first)
            XCTAssertEqual(finding.guardVerdict, "blocks")
            XCTAssertEqual(finding.mcp, "placeholder, restored on write")
            XCTAssertEqual(finding.proxy, "redacted outbound")
        }
    }

    // WO-639: decoded tool arguments retain whole-match identity for UUID-based replacement.
    func testEscapedToolCallPasswordUsesAuthorizedSubrange() throws {
        let password = fixturePassword()
        let connection = fixtureConnection(password)
        let escaped = connection.unicodeScalars.map { String(format: "\\u%04x", $0.value) }.joined()
        let arguments = "{\"connection\":\"" + escaped + "\"}"
        let payload = try JSONSerialization.data(withJSONObject: [
            "type": "content_block_delta", "index": 0,
            "delta": ["type": "input_json_delta", "partial_json": arguments]
        ])
        let stream = Data("event: content_block_delta\ndata: ".utf8) + payload + Data("\n\n".utf8)
        var parser = SSEFrameParser()
        let frame = try XCTUnwrap(parser.feed(stream).frames.first)
        var transformer = ToolCallStreamRedactor(config: fixtureConfig(), customRules: [], severity: .high)
        let pending = transformer.process(frame)
        XCTAssertFalse(pending.terminateStream)
        let completed = transformer.finish()
        XCTAssertFalse(completed.terminateStream)
        let frames = pending.frames + completed.frames
        XCTAssertEqual(frames.reduce(0) { $0 + $1.toolCallRedactionCount }, 1)
        var outputParser = SSEFrameParser()
        let output = frames.reduce(into: Data()) { $0.append($1.data) }
        let data = try XCTUnwrap(outputParser.feed(output).frames.first?.data)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(data.utf8)) as? [String: Any])
        let delta = try XCTUnwrap(object["delta"] as? [String: Any])
        let redactedArguments = try XCTUnwrap(delta["partial_json"] as? String)
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(redactedArguments.utf8)) as? [String: Any])
        let actual = try XCTUnwrap(decoded["connection"] as? String)
        let marker = Obfuscator.makePlaceholder(type: .dbConnectionString, number: 1)
        XCTAssertFalse(actual.contains(password))
        XCTAssertTrue(actual == marker)
    }

    // WO-639: whole-match lookup must target the detected DSN, not an earlier unmatched password.
    func testNonUTF8ResponsePasswordUsesDetectedOccurrence() {
        let password = fixturePassword()
        let connection = fixtureConnection(password)
        let prefix = Data([0xFF]) + Data(("unmatched " + password + "\n").utf8)
        let body = prefix + Data(connection.utf8)
        let result = CurlHTTPClient.redactNonUTF8ResponseBody(body, config: fixtureConfig(), severity: .high)
        let marker = Obfuscator.makePlaceholder(type: .dbConnectionString, number: 1)
        XCTAssertEqual(result.count, 1)
        XCTAssertFalse(result.data.range(of: Data(connection.utf8)) != nil)
        XCTAssertTrue(result.data == prefix + Data(marker.utf8))
        XCTAssertTrue(result.data.prefix(prefix.count) == prefix)
        assertNoPassword(Data(result.data.dropFirst(prefix.count)), password: password,
                         count: result.count, surface: "detected binary occurrence")
    }

    // WO-639: loss of optional targeting data must redact more, never expose a proved password.
    func testDroppedSubrangeOverRedactsAndStillRestoresWholeConnection() throws {
        let connection = fixtureConnection(fixturePassword())
        let content = "prefix\n" + connection + "\nsuffix"
        let original = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
        let copied = DetectedMatch(
            type: original.type, value: original.value, range: original.range, line: original.line,
            mutationAuthorizationSources: original.mutationAuthorizationSources
        )
        let partition = partitionMutationMatches([copied], site: .mcpRead, minAdvisorySeverity: .high)
        XCTAssertEqual(partition.authorized.count, 1)
        let store = RedactionStore()
        let (redacted, entries) = store.redact(content: content, matches: partition.authorized, filePath: "guide.md")
        let marker = try XCTUnwrap(entries.first?.placeholder)
        XCTAssertTrue(redacted == "prefix\n" + marker + "\nsuffix")
        XCTAssertTrue(store.resolve(content: redacted, filePath: "guide.md").content == content)
    }

    // WO-639: subrange conversion respects non-ASCII text before and inside a connection, including bridged strings.
    func testMCPPasswordSpanPreservesUnicodeContainerAndRestoresBytes() throws {
        let password = "\u{00E9}" + fixturePassword()
        let connection = fixtureConnection(password)
        let content = String(repeating: "\u{1F511} \u{00E9}\n", count: 20) + connection + "\nend"
        let units = Array(content.utf16)
        let bridged = units.withUnsafeBufferPointer { NSString(characters: $0.baseAddress!, length: $0.count) as String }
        for input in [content, bridged] {
            let config = fixtureConfig()
            let matches = DetectionRules.scan(input, config: config)
            let original = try XCTUnwrap(matches.first)
            XCTAssertNotNil(original.mutationSubrange)
            XCTAssertTrue(original.value == connection)
            let decision = MCPReadDecision.evaluate(
                matches: matches, content: input, config: config, minimumSeverity: .high, filePath: "guide.md"
            )
            XCTAssertEqual(decision.authorized.count, 1)
            XCTAssertTrue(decision.reportedAdvisories.isEmpty)
            let store = RedactionStore()
            let (redacted, entries) = store.redact(content: input, matches: decision.authorized, filePath: "guide.md")
            let marker = try XCTUnwrap(entries.first?.placeholder)
            XCTAssertTrue(redacted == input.replacingOccurrences(of: password, with: marker))
            let restored = store.resolve(content: redacted, filePath: "guide.md")
            XCTAssertTrue(Data(restored.content.utf8) == Data(input.utf8))
        }
    }

    // WO-639: targeting alone never authorizes mutation and unusable targets fail toward whole-value replacement.
    func testSubrangeDoesNotGrantAuthorizationAndInvalidTargetsOverRedact() throws {
        let connection = fixtureConnection(fixturePassword())
        let content = "prefix " + connection
        let original = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
        let advisory = DetectedMatch(
            type: original.type, value: original.value, range: original.range,
            mutationAuthorizationSources: [], mutationSubrange: original.mutationSubrange
        )
        let advisoryPartition = partitionMutationMatches([advisory], site: .mcpRead, minAdvisorySeverity: .high)
        XCTAssertTrue(advisoryPartition.authorized.isEmpty)
        XCTAssertTrue(advisoryPartition.advisory.first?.value == connection)
        for span in [content.startIndex..<content.endIndex, original.range.lowerBound..<original.range.lowerBound] {
            let invalid = DetectedMatch(
                type: original.type, value: original.value, range: original.range,
                mutationAuthorizationSources: original.mutationAuthorizationSources, mutationSubrange: span
            )
            let outcome = applyAuthorizedMutations(to: content, matches: [invalid], site: .mcpRead, minAdvisorySeverity: .high)
            XCTAssertEqual(outcome.mutated.count, 1)
            XCTAssertTrue(outcome.text == "prefix " + Obfuscator.makePlaceholder(type: .dbConnectionString, number: 1))
        }
    }

    // WO-639: partitioning retains whole-match identity; only text-rewriting primitives use targeting.
    func testAuthorizedPartitionRetainsWholeMatchIdentityAndMetadata() throws {
        let password = fixturePassword()
        let content = "prefix\n" + fixtureConnection(password)
        let original = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
        let match = DetectedMatch(
            type: original.type, value: original.value, range: original.range, line: 2, filePath: "guide.md",
            customRuleName: "fixture-rule", customSeverity: .high, mutationAuthorizationSources: [.intrinsicFormat],
            obfuscateRuleIdentifier: "fixture-id", mutationSubrange: original.mutationSubrange
        )
        let first = try XCTUnwrap(partitionMutationMatches([match], site: .mcpRead, minAdvisorySeverity: .high).authorized.first)
        XCTAssertEqual(first.id, match.id)
        XCTAssertTrue(first.value == match.value)
        XCTAssertEqual(first.range, match.range)
        XCTAssertEqual(first.line, 2)
        XCTAssertEqual(first.filePath, "guide.md")
        XCTAssertEqual(first.customRuleName, "fixture-rule")
        XCTAssertEqual(first.effectiveSeverity, .high)
        XCTAssertEqual(first.obfuscateRuleIdentifier, "fixture-id")
        XCTAssertEqual(first.mutationAuthorizationSources, match.mutationAuthorizationSources)
        XCTAssertEqual(first.mutationSubrange, match.mutationSubrange)
        let second = try XCTUnwrap(partitionMutationMatches([first], site: .mcpRead, minAdvisorySeverity: .high).authorized.first)
        XCTAssertEqual(second.id, match.id)
        XCTAssertTrue(second.value == match.value)
        XCTAssertEqual(second.range, first.range)
    }

    // WO-645@v1: capture the duplicate writer's byte-exact password-only output before removal.
    func testDSNRewriteGoldenBytesBeforeResolverExtraction() throws {
        let first = fixtureConnection(fixturePassword())
        let second = fixtureConnection(["Z8q", "R3s", "M9V", "4tP", "7d"].joined())
        let content = "\u{1F600} first " + first + " next " + second + " tail"
        let matches = DetectionRules.scan(content, config: fixtureConfig())
        XCTAssertEqual(matches.count, 2)
        let expected = "\u{1F600} first " + fixtureConnection("<DB_CONNECTION_1>") +
            " next " + fixtureConnection("<DB_CONNECTION_2>") + " tail"
        let result = applyAuthorizedMutations(to: content, matches: Array(matches.reversed()),
                                             site: .proxyUserText, minAdvisorySeverity: .high)
        XCTAssertTrue(result.text.utf8.elementsEqual(expected.utf8))
    }

    // WO-645@v1: the shared resolver must reproduce the duplicate writer's captured DSN output.
    func testObfuscatorDSNResolverMatchesCapturedGoldenBytes() throws {
        let content = "\u{1F600} first " + fixtureConnection(fixturePassword()) + " tail"
        let matches = DetectionRules.scan(content, config: fixtureConfig())
        XCTAssertEqual(matches.count, 1)
        let expected = "\u{1F600} first " + fixtureConnection("<DB_CONNECTION_1>") + " tail"
        let actual = Obfuscator.obfuscate(content, matches: matches, replacementRange: {
            authorizedMutationRange(for: $0, in: content)
        })
        XCTAssertTrue(actual.utf8.elementsEqual(expected.utf8))
    }

    // WO-639: every mutation site preserves finding identity while removing the detected password.
    func testEveryMutationSiteRemovesPasswordWithoutNarrowingMatchIdentity() throws {
        let password = fixturePassword()
        let content = fixtureConnection(password)
        let match = try XCTUnwrap(DetectionRules.scan(content, config: fixtureConfig()).first)
        for site in MutationSite.allCases {
            let result = applyAuthorizedMutations(to: content, matches: [match], site: site, minAdvisorySeverity: .high)
            XCTAssertEqual(result.mutated.count, 1, "site \(site)")
            XCTAssertEqual(result.mutated.first?.id, match.id, "site \(site)")
            XCTAssertTrue(result.mutated.first?.value == match.value, "site \(site)")
            XCTAssertEqual(result.mutated.first?.range, match.range, "site \(site)")
            assertNoPassword(Data(result.text.utf8), password: password, count: result.mutated.count, surface: "site \(site)")
        }
    }

    // WO-639: every authored request field and the batch walker use the same password-safe rewrite.
    func testProxyRequestSurfacesNeverReturnDetectedPassword() throws {
        let server = ProxyServer(config: fixtureConfig(), quietLog: true)
        for password in [fixturePassword(), "\u{00E9}" + fixturePassword()] {
            let connection = fixtureConnection(password)
            for (surface, fields) in requestFixtures(connection) {
                var body: [String: Any] = ["model": "claude-test", "max_tokens": 1, "messages": []]
                fields.forEach { body[$0.key] = $0.value }
                for batch in [false, true] {
                    let request = batch ? ["requests": [["custom_id": "fixture", "params": body]]] : body
                    let data = try JSONSerialization.data(withJSONObject: request)
                    let result = server.scanAndRedactBody(try XCTUnwrap(String(data: data, encoding: .utf8)))
                    XCTAssertFalse(result.serializationFailed, "surface \(surface), batch \(batch)")
                    assertNoPassword(Data(result.body.utf8), password: password, count: result.redacted, surface: surface)
                }
            }
        }
    }

    // WO-639: cover every response writer except the two explicitly deferred WO-641 Unicode binary cases.
    func testProxyResponseSurfacesNeverReturnDetectedPassword() throws {
        let config = fixtureConfig()
        for (variant, password) in [fixturePassword(), "\u{00E9}" + fixturePassword()].enumerated() {
            let body = Data((fixtureConnection(password) + "\n").utf8)
            let binary = Data([0xFF]) + body
            var results = [
                ("buffered-text", CurlHTTPClient.redactBufferedResponseBody(body, config: config, severity: .high)),
                ("raw-stream", redactRawStreamBytes(body, config: config, severity: .high)),
                ("raw-binary-stream", redactRawStreamBytes(binary, config: config, severity: .high))
            ]
            if password.utf8.allSatisfy({ $0 < 0x80 }) {
                results.append(("buffered-binary", CurlHTTPClient.redactBufferedResponseBody(binary, config: config, severity: .high)))
                results.append(("non-UTF8", CurlHTTPClient.redactNonUTF8ResponseBody(binary, config: config, severity: .high)))
            }
            for (surface, result) in results {
                assertNoPassword(result.data, password: password, count: result.count, surface: "\(surface), variant \(variant)")
            }
            let payload = try JSONSerialization.data(withJSONObject: [
                "type": "content_block_delta", "delta": ["type": "text_delta", "text": fixtureConnection(password)]
            ])
            for data in [payload, body] {
                var parser = SSEFrameParser()
                let frame = try XCTUnwrap(parser.feed(Data("data: ".utf8) + data + Data("\n\n".utf8)).frames.first)
                let result = redactSSEFrame(frame, config: config, severity: .high)
                assertNoPassword(result.data, password: password, count: result.count, surface: "SSE, variant \(variant)")
            }
        }
    }

    // WO-641@v2: both binary response entry points remove the authorized multibyte password.
    func testKnownGapWO641NonASCIISecretsRemainInBinaryResponses() throws {
        let password = "\u{00E9}" + fixturePassword()
        let content = fixtureConnection(password) + "\n"
        let config = fixtureConfig()
        let match = try XCTUnwrap(DetectionRules.scan(content, config: config).first)
        XCTAssertEqual(partitionMutationMatches([match], site: .proxyResponse, minAdvisorySeverity: .high).authorized.count, 1)
        let binary = Data([0xFF]) + Data(content.utf8)
        let results = [
            CurlHTTPClient.redactBufferedResponseBody(binary, config: config, severity: .high),
            CurlHTTPClient.redactNonUTF8ResponseBody(binary, config: config, severity: .high)
        ]
        for result in results {
            // WO-641@v2: binary prefixes stay byte-exact and successful counts describe actual replacements.
            XCTAssertEqual(result.count, 1)
            XCTAssertTrue(result.data.first == binary.first)
            XCTAssertNil(result.data.range(of: Data(password.utf8)))
        }
    }

    // WO-639: OpenAI and Anthropic escaped argument streams must both perform the counted replacement.
    func testOpenAIToolArgumentStreamNeverReturnsDetectedPassword() throws {
        let password = fixturePassword()
        let escaped = fixtureConnection(password).unicodeScalars.map { String(format: "\\u%04x", $0.value) }.joined()
        let arguments = "{\"connection\":\"" + escaped + "\"}"
        let payload = try JSONSerialization.data(withJSONObject: ["choices": [[
            "index": 0, "delta": ["tool_calls": [["index": 0, "function": ["arguments": arguments]]]]
        ]]])
        var parser = SSEFrameParser()
        let frame = try XCTUnwrap(parser.feed(Data("data: ".utf8) + payload + Data("\n\n".utf8)).frames.first)
        var transformer = ToolCallStreamRedactor(config: fixtureConfig(), customRules: [], severity: .high)
        let pending = transformer.process(frame)
        let completed = transformer.finish()
        XCTAssertFalse(pending.terminateStream || completed.terminateStream)
        let frames = pending.frames + completed.frames
        let output = frames.reduce(into: Data()) { $0.append($1.data) }
        assertNoPassword(output, password: password, count: frames.reduce(0) { $0 + $1.toolCallRedactionCount }, surface: "OpenAI tool")
        var outputParser = SSEFrameParser()
        let data = try XCTUnwrap(outputParser.feed(output).frames.first?.data)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(data.utf8)) as? [String: Any])
        let choices = try XCTUnwrap(object["choices"] as? [[String: Any]])
        let delta = try XCTUnwrap(choices.first?["delta"] as? [String: Any])
        let calls = try XCTUnwrap(delta["tool_calls"] as? [[String: Any]])
        let function = try XCTUnwrap(calls.first?["function"] as? [String: Any])
        let redacted = try XCTUnwrap(function["arguments"] as? String)
        let inner = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(redacted.utf8)) as? [String: Any])
        let actual = try XCTUnwrap(inner["connection"] as? String)
        XCTAssertFalse(actual.contains(password))
        XCTAssertTrue(actual == Obfuscator.makePlaceholder(type: .dbConnectionString, number: 1))
    }

    // WO-639: MCP diagnostics, full/ranged reads and write acknowledgments never return the password.
    func testMCPOutputSurfacesNeverReturnDetectedPassword() throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536, config: fixtureConfig())
            defer { session.close() }
            let password = fixturePassword()
            let content = fixtureConnection(password) + "\n"
            let path = session.directory.appendingPathComponent("fixture.env")
            try Data(content.utf8).write(to: path)
            let calls: [(String, [String: JSONValue])] = [
                ("pastewatch_scan", ["text": .string(content)]),
                ("pastewatch_scan_file", ["path": .string(path.path)]),
                ("pastewatch_scan_dir", ["path": .string(session.directory.path)]),
                ("pastewatch_check_output", ["text": .string(content)])
            ]
            for (name, arguments) in calls {
                let response = try mcpResponse(session, name: name, arguments: arguments)
                XCTAssertNil(try JSONEncoder().encode(response).range(of: Data(password.utf8)), "surface \(name)")
            }
            let payload = try mcpPayload(session, name: "pastewatch_read_file", arguments: ["path": .string(path.path)])
            let redacted = try XCTUnwrap(payload["content"] as? String)
            XCTAssertFalse(redacted.contains(password))
            let ranged = try mcpPayload(session, name: "pastewatch_read_file", arguments: [
                "path": .string(path.path), "byte_offset": .number(0), "byte_length": .number(65_536)
            ])
            let encoded = try XCTUnwrap(ranged["content"] as? String)
            let decoded = try XCTUnwrap(Data(base64Encoded: encoded))
            XCTAssertNil(decoded.range(of: Data(password.utf8)))
            XCTAssertTrue(decoded == Data(redacted.utf8))
            let written = try mcpResponse(session, name: "pastewatch_write_file", arguments: [
                "path": .string(path.path), "content": .string(redacted)
            ])
            XCTAssertNil(try JSONEncoder().encode(written).range(of: Data(password.utf8)))
            XCTAssertTrue(try Data(contentsOf: path) == Data(content.utf8))
        }
    }

    // WO-639: assert privacy and actual replacement counts without disclosing fixture values on failure.
    private func assertNoPassword(_ output: Data, password: String, count: Int, surface: String) {
        XCTAssertNil(output.range(of: Data(password.utf8)), "surface \(surface): detected password remains")
        XCTAssertEqual(count, 1, "surface \(surface): exactly one detected connection")
        let marker = Data(Obfuscator.makePlaceholder(type: .dbConnectionString, number: 1).utf8)
        let first = output.range(of: marker)
        XCTAssertNotNil(first, "surface \(surface): counted replacement must exist")
        if let first {
            XCTAssertNil(output.range(of: marker, in: first.upperBound..<output.endIndex),
                         "surface \(surface): replacement count must be exact")
        }
    }

    // WO-639: enumerate request containers so a surface cannot pass solely through a neighboring field.
    private func requestFixtures(_ connection: String) -> [(String, [String: Any])] {
        let text = ["type": "text", "text": connection]
        let toolUse: [String: Any] = ["type": "tool_use", "id": "one", "name": "fixture", "input": ["value": connection]]
        let toolResult: [String: Any] = ["type": "tool_result", "tool_use_id": "one", "content": connection]
        let toolResultBlocks: [String: Any] = ["type": "tool_result", "tool_use_id": "one", "content": [text]]
        return [
            ("system-string", ["system": connection]),
            ("system-array", ["system": [text]]),
            ("tool-description", ["tools": [["name": "fixture", "description": connection, "input_schema": ["type": "object"]]]]),
            ("tool-schema", ["tools": [["name": "fixture", "input_schema": ["type": "object", "description": connection]]]]),
            ("tool-examples", ["tools": [[
                "name": "fixture", "input_schema": ["type": "object"], "input_examples": [["value": connection]]
            ]]]),
            ("user-string", ["messages": [["role": "user", "content": connection]]]),
            ("user-block", ["messages": [["role": "user", "content": [text]]]]),
            ("assistant-string", ["messages": [["role": "assistant", "content": connection]]]),
            ("assistant-block", ["messages": [["role": "assistant", "content": [text]]]]),
            ("tool-input", ["messages": [["role": "assistant", "content": [toolUse]]]]),
            ("tool-result", ["messages": [["role": "user", "content": [toolResult]]]]),
            ("tool-result-block", ["messages": [["role": "user", "content": [toolResultBlocks]]]]),
            ("stop-sequence", ["stop_sequences": [connection]])
        ]
    }

    // WO-639: deterministic synthetic values are assembled only at runtime.
    private func fixturePassword() -> String {
        ["Q7m", "N4r", "Z9T", "2xV", "6k"].joined()
    }

    // WO-639: separate the tested userinfo from its surrounding container.
    private func fixtureConnection(_ password: String) -> String {
        ["post", "gres", "://", "app:", password, "@db:5432/prod"].joined()
    }

    // WO-639: explicit fixture policy never resolves operator configuration.
    private func fixtureConfig() -> PastewatchConfig {
        TestConfigHelper.configWithAmbiguousAdvisories([.credential, .dbConnectionString])
    }

    // WO-639: use real MCP processes with project-only fixture policy, never operator files.
    private func assertMCPFormats(_ extensions: [String]) throws {
        try TestConfigHelper.withIsolatedGlobalConfig { _ in
            let session = try MCPProtocolTests.LiveMCPSession(executableURL: cliURL(), maximumLineBytes: 65_536, config: fixtureConfig())
            defer { session.close() }
            let password = "\u{00E9}" + fixturePassword()
            let connection = fixtureConnection(password)
            for ext in extensions {
                for position in 0..<3 {
                    let content = formatFixture(connection, ext: ext, position: position)
                    let path = session.directory.appendingPathComponent("fixture-\(position).\(ext)")
                    try Data(content.utf8).write(to: path)
                    let payload = try mcpPayload(session, name: "pastewatch_read_file", arguments: ["path": .string(path.path)])
                    let entries = try XCTUnwrap(payload["redactions"] as? [[String: Any]])
                    XCTAssertEqual(entries.count, 1)
                    let marker = try XCTUnwrap(entries.first?["placeholder"] as? String)
                    let redacted = try XCTUnwrap(payload["content"] as? String)
                    XCTAssertFalse(redacted.contains(password))
                    XCTAssertEqual(redacted.components(separatedBy: marker).count - 1, entries.count)
                    XCTAssertTrue(redacted == content.replacingOccurrences(of: password, with: marker),
                                  "format \(ext), prefix variant \(position): only the password may change")
                    _ = try mcpPayload(session, name: "pastewatch_write_file", arguments: [
                        "path": .string(path.path), "content": .string(redacted + "\n")
                    ])
                    XCTAssertTrue(try Data(contentsOf: path) == Data((content + "\n").utf8),
                                  "MCP write must restore bytes while applying the requested newline")
                }
            }
        }
    }

    // WO-639: vary only the source format and astral-prefix placement; the DSN is identical.
    private func formatFixture(_ connection: String, ext: String, position: Int) -> String {
        let emoji = "\u{1F511}"
        let value = (position == 1 ? emoji + " note " : "") + connection
        let previous = position == 2 ? "# " + emoji + " note\n" : ""
        switch ext {
        case "env": return previous + "DATABASE_URL=\"" + value + "\"\n"
        case "json":
            return "{" + (position == 2 ? "\"note\":\"" + emoji + "\",\n" : "") + "\"connection\":\"" + value + "\"}\n"
        case "yaml": return previous + "connection: \"" + value + "\"\n"
        default: return previous + value + "\n"
        }
    }

    // WO-639: parse only protocol metadata; assertion diagnostics never include the fixture payload.
    private func mcpPayload(
        _ session: MCPProtocolTests.LiveMCPSession, name: String, arguments: [String: JSONValue]
    ) throws -> [String: Any] {
        let response = try mcpResponse(session, name: name, arguments: arguments)
        guard case .object(let result) = response.result,
              case .array(let blocks) = result["content"], case .object(let block) = blocks.first,
              case .string(let text) = block["text"] else {
            throw NSError(domain: "DSNPasswordEvidenceTests", code: 1)
        }
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    // WO-639: share live transport validation across JSON payload and diagnostic-only tool outputs.
    private func mcpResponse(
        _ session: MCPProtocolTests.LiveMCPSession, name: String, arguments: [String: JSONValue]
    ) throws -> JSONRPCResponse {
        let request = JSONRPCRequest(jsonrpc: "2.0", id: .int(1), method: "tools/call", params: .object([
            "name": .string(name), "arguments": .object(arguments)
        ]))
        try session.send(JSONEncoder().encode(request) + Data([0x0A]))
        let response = try XCTUnwrap(session.response(), "MCP response deadline expired")
        XCTAssertTrue(response.error == nil)
        guard case .object(let result) = response.result else {
            throw NSError(domain: "DSNPasswordEvidenceTests", code: 1)
        }
        XCTAssertNil(result["isError"])
        return response
    }

    // WO-639: derive the binary location without resolving configuration in an operator directory.
    private func cliURL() -> URL {
        let bundled = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("PastewatchCLI")
        if FileManager.default.fileExists(atPath: bundled.path) { return bundled }
        return repositoryRoot().appendingPathComponent(".build/debug/PastewatchCLI")
    }

    // WO-639: documentation tests read only the public repository artifact.
    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }
}
