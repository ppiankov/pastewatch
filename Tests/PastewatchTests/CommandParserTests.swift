import XCTest
@testable import PastewatchCore

final class CommandParserTests: XCTestCase {

    // MARK: - File readers

    func testCatExtractsFile() {
        let paths = CommandParser.extractFilePaths(from: "cat /app/.env")
        XCTAssertEqual(paths, ["/app/.env"])
    }

    func testCatExtractsMultipleFiles() {
        let paths = CommandParser.extractFilePaths(from: "cat /app/.env /app/config.yml")
        XCTAssertEqual(paths, ["/app/.env", "/app/config.yml"])
    }

    func testHeadSkipsFlags() {
        let paths = CommandParser.extractFilePaths(from: "head -n 10 /app/log.txt")
        XCTAssertEqual(paths, ["/app/log.txt"])
    }

    func testTailWithFlag() {
        let paths = CommandParser.extractFilePaths(from: "tail -f /var/log/app.log")
        XCTAssertEqual(paths, ["/var/log/app.log"])
    }

    // MARK: - File writers

    func testSedExtractsFileArg() {
        let paths = CommandParser.extractFilePaths(from: "sed -i 's/old/new/' /app/config.yml")
        XCTAssertEqual(paths, ["/app/config.yml"])
    }

    func testAwkExtractsFileArg() {
        let paths = CommandParser.extractFilePaths(from: "awk '{print $1}' /app/data.csv")
        XCTAssertEqual(paths, ["/app/data.csv"])
    }

    // MARK: - File searchers

    func testGrepExtractsFileAfterPattern() {
        let paths = CommandParser.extractFilePaths(from: "grep password /app/config.yml")
        XCTAssertEqual(paths, ["/app/config.yml"])
    }

    func testGrepWithFlagsExtractsFile() {
        let paths = CommandParser.extractFilePaths(from: "grep -i -n password /app/config.yml")
        XCTAssertEqual(paths, ["/app/config.yml"])
    }

    // MARK: - Source commands

    func testSourceExtractsFile() {
        let paths = CommandParser.extractFilePaths(from: "source /app/.env")
        XCTAssertEqual(paths, ["/app/.env"])
    }

    func testDotSourceExtractsFile() {
        let paths = CommandParser.extractFilePaths(from: ". /app/.env")
        XCTAssertEqual(paths, ["/app/.env"])
    }

    // MARK: - Unknown commands

    func testEchoReturnsEmpty() {
        let paths = CommandParser.extractFilePaths(from: "echo hello")
        XCTAssertTrue(paths.isEmpty)
    }

    func testLsReturnsEmpty() {
        let paths = CommandParser.extractFilePaths(from: "ls -la /app")
        XCTAssertTrue(paths.isEmpty)
    }

    func testEmptyCommandReturnsEmpty() {
        let paths = CommandParser.extractFilePaths(from: "")
        XCTAssertTrue(paths.isEmpty)
    }

    // MARK: - Path prefix stripping

    func testFullPathCommandStripped() {
        let paths = CommandParser.extractFilePaths(from: "/usr/bin/cat /app/.env")
        XCTAssertEqual(paths, ["/app/.env"])
    }

    // MARK: - Quoted arguments

    func testDoubleQuotedPath() {
        let paths = CommandParser.extractFilePaths(from: "cat \"/app/my file.txt\"")
        XCTAssertEqual(paths, ["/app/my file.txt"])
    }

    func testSingleQuotedPath() {
        let paths = CommandParser.extractFilePaths(from: "cat '/app/my file.txt'")
        XCTAssertEqual(paths, ["/app/my file.txt"])
    }

    // MARK: - Relative path resolution

    func testRelativePathResolved() {
        let paths = CommandParser.extractFilePaths(from: "cat ./config.yml", workingDirectory: "/app")
        XCTAssertEqual(paths, ["/app/config.yml"])
    }

    func testBareFilenameResolved() {
        let paths = CommandParser.extractFilePaths(from: "cat config.yml", workingDirectory: "/app")
        XCTAssertEqual(paths, ["/app/config.yml"])
    }

    // MARK: - Tokenizer

    func testTokenizeSimple() {
        let tokens = CommandParser.tokenize("cat file.txt")
        XCTAssertEqual(tokens, ["cat", "file.txt"])
    }

    func testTokenizeQuoted() {
        let tokens = CommandParser.tokenize("grep \"hello world\" file.txt")
        XCTAssertEqual(tokens, ["grep", "hello world", "file.txt"])
    }

    func testTokenizeEscapedSpace() {
        let tokens = CommandParser.tokenize("cat file\\ name.txt")
        XCTAssertEqual(tokens, ["cat", "file name.txt"])
    }

    func testTokenizeMixedQuotes() {
        let tokens = CommandParser.tokenize("sed -i 's/old/new/' file.txt")
        XCTAssertEqual(tokens, ["sed", "-i", "s/old/new/", "file.txt"])
    }

    // MARK: - Infrastructure tools

    func testAnsiblePlaybookInventoryAndPlaybook() {
        let paths = CommandParser.extractFilePaths(
            from: "ansible-playbook -i /app/inventory/production /app/deploy.yml --tags cron --check"
        )
        XCTAssertEqual(paths, ["/app/inventory/production", "/app/deploy.yml"])
    }

    func testAnsiblePlaybookLongInventoryFlag() {
        let paths = CommandParser.extractFilePaths(
            from: "ansible-playbook --inventory /app/hosts.ini /app/site.yml"
        )
        XCTAssertEqual(paths, ["/app/hosts.ini", "/app/site.yml"])
    }

    func testAnsiblePlaybookExtraVarsFile() {
        let paths = CommandParser.extractFilePaths(
            from: "ansible-playbook -e @/app/secrets.yml /app/deploy.yml"
        )
        XCTAssertEqual(paths, ["/app/secrets.yml", "/app/deploy.yml"])
    }

    func testDockerComposeFileFlag() {
        let paths = CommandParser.extractFilePaths(
            from: "docker-compose -f /app/docker-compose.yml up"
        )
        XCTAssertEqual(paths, ["/app/docker-compose.yml"])
    }

    func testDockerEnvFileFlag() {
        let paths = CommandParser.extractFilePaths(
            from: "docker run --env-file /app/.env myimage"
        )
        XCTAssertEqual(paths, ["/app/.env"])
    }

    func testKubectlApplyFile() {
        let paths = CommandParser.extractFilePaths(
            from: "kubectl apply -f /app/k8s/deployment.yaml"
        )
        XCTAssertEqual(paths, ["/app/k8s/deployment.yaml"])
    }

    func testHelmValuesFile() {
        let paths = CommandParser.extractFilePaths(
            from: "helm install myrelease /app/chart -f /app/values.yaml"
        )
        XCTAssertTrue(paths.contains("/app/values.yaml"))
        XCTAssertTrue(paths.contains("/app/chart"))
    }

    func testTerraformVarFileEquals() {
        let paths = CommandParser.extractFilePaths(
            from: "terraform plan -var-file=/app/prod.tfvars"
        )
        XCTAssertEqual(paths, ["/app/prod.tfvars"])
    }

    func testInfraToolSkipsNonPathPositionals() {
        // "up" doesn't look like a file path — no / or . or known extension
        let paths = CommandParser.extractFilePaths(
            from: "docker-compose up"
        )
        XCTAssertTrue(paths.isEmpty)
    }

    // MARK: - Scripting interpreters

    func testPython3ScriptFile() {
        let paths = CommandParser.extractFilePaths(from: "python3 /app/script.py")
        XCTAssertEqual(paths, ["/app/script.py"])
    }

    func testPythonSkipsInlineCode() {
        // -c takes inline code — can't parse file paths from it
        let paths = CommandParser.extractFilePaths(from: "python3 -c 'import os; print(os.environ)'")
        XCTAssertTrue(paths.isEmpty)
    }

    func testRubyScriptFile() {
        let paths = CommandParser.extractFilePaths(from: "ruby /app/deploy.rb")
        XCTAssertEqual(paths, ["/app/deploy.rb"])
    }

    func testRubySkipsInlineFlag() {
        let paths = CommandParser.extractFilePaths(from: "ruby -e 'puts 1'")
        XCTAssertTrue(paths.isEmpty)
    }

    func testNodeScriptFile() {
        let paths = CommandParser.extractFilePaths(from: "node /app/server.js")
        XCTAssertEqual(paths, ["/app/server.js"])
    }

    func testPerlScriptFile() {
        let paths = CommandParser.extractFilePaths(from: "perl /app/process.pl")
        XCTAssertEqual(paths, ["/app/process.pl"])
    }

    func testPython3WithFlags() {
        let paths = CommandParser.extractFilePaths(from: "python3 -u /app/script.py")
        XCTAssertEqual(paths, ["/app/script.py"])
    }

    // MARK: - File transfer tools

    func testScpLocalFile() {
        let paths = CommandParser.extractFilePaths(from: "scp /app/.env user@remote:/tmp/")
        XCTAssertEqual(paths, ["/app/.env"])
    }

    func testScpSkipsRemotePaths() {
        let paths = CommandParser.extractFilePaths(from: "scp user@remote:/tmp/file.txt /app/local.txt")
        XCTAssertEqual(paths, ["/app/local.txt"])
    }

    func testSshIdentityFile() {
        let paths = CommandParser.extractFilePaths(from: "ssh -i /app/.ssh/id_rsa user@host")
        XCTAssertEqual(paths, ["/app/.ssh/id_rsa"])
    }

    func testRsyncPasswordFile() {
        let paths = CommandParser.extractFilePaths(from: "rsync --password-file /app/.rsync-pass /src/ remote:/dst/")
        XCTAssertTrue(paths.contains("/app/.rsync-pass"))
        XCTAssertTrue(paths.contains("/src/"))
    }

    // MARK: - Pipe chains

    func testPipeChain() {
        let paths = CommandParser.extractFilePaths(from: "cat /app/.env | base64")
        XCTAssertEqual(paths, ["/app/.env"])
    }

    func testMultiPipeChain() {
        let paths = CommandParser.extractFilePaths(from: "cat /app/.env | grep password | head -1")
        XCTAssertEqual(paths, ["/app/.env"])
    }

    func testAndChain() {
        let paths = CommandParser.extractFilePaths(from: "cat /app/.env && cat /app/config.yml")
        XCTAssertTrue(paths.contains("/app/.env"))
        XCTAssertTrue(paths.contains("/app/config.yml"))
    }

    func testOrChain() {
        let paths = CommandParser.extractFilePaths(from: "cat /app/.env || cat /app/fallback.yml")
        XCTAssertTrue(paths.contains("/app/.env"))
        XCTAssertTrue(paths.contains("/app/fallback.yml"))
    }

    func testSemicolonChain() {
        let paths = CommandParser.extractFilePaths(from: "cat /app/.env; head /app/secrets.txt")
        XCTAssertTrue(paths.contains("/app/.env"))
        XCTAssertTrue(paths.contains("/app/secrets.txt"))
    }

    func testPipeInsideQuotesNotSplit() {
        let paths = CommandParser.extractFilePaths(from: "grep 'foo|bar' /app/config.yml")
        XCTAssertEqual(paths, ["/app/config.yml"])
    }

    func testSplitCommandChainSimple() {
        let segments = CommandParser.splitCommandChain("cat file.txt | grep secret")
        XCTAssertEqual(segments, ["cat file.txt", "grep secret"])
    }

    func testSplitCommandChainPreservesQuotedPipes() {
        let segments = CommandParser.splitCommandChain("grep 'a|b' file.txt")
        XCTAssertEqual(segments, ["grep 'a|b' file.txt"])
    }

    func testSplitCommandChainMultipleOperators() {
        let segments = CommandParser.splitCommandChain("cmd1 && cmd2 || cmd3; cmd4 | cmd5")
        XCTAssertEqual(segments, ["cmd1", "cmd2", "cmd3", "cmd4", "cmd5"])
    }
}
