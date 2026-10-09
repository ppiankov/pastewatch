import Foundation
import XCTest
@testable import PastewatchCLI
@testable import PastewatchCore

// WO-671@v2: stale-server diagnostics use fixture processes and clocks, not the host process table.
final class DoctorMCPStalenessTests: XCTestCase {
    // WO-671@v2: an old start or a different reported version independently requires reconnection.
    func testOldStartAndDifferentVersionWarnWithRemedy() throws {
        let doctor = try Doctor.parse([])
        let processes = [
            MCPProcessSnapshot(pid: 17, startedAt: instant(10), serverVersion: AppVersion.current),
            MCPProcessSnapshot(pid: 18, startedAt: instant(30), serverVersion: "0.0.0"),
            MCPProcessSnapshot(pid: 19, startedAt: instant(30), serverVersion: AppVersion.current),
        ]
        var clockCalls = 0
        let rows = doctor.checkMCPProcesses(processList: { processes }, binaryModifiedAt: { self.instant(20) }, clock: {
            clockCalls += 1
            return self.instant(80)
        })
        XCTAssertEqual(clockCalls, 1)
        XCTAssertEqual(rows.count, 4)
        XCTAssertEqual(rows[0].status, "warn")
        for row in rows[1...2] {
            XCTAssertEqual(row.status, "warn")
            XCTAssertTrue(row.detail.contains("reconnect MCP or restart the agent session"))
        }
        XCTAssertTrue(rows[1].detail.contains("started before the installed binary"))
        XCTAssertTrue(rows[2].detail.contains("server version"))
        XCTAssertEqual(rows[3].status, "info")
        XCTAssertFalse(rows[3].detail.contains("reconnect"))
    }

    // WO-671@v2: equal timestamps are not older; age and existing process flags remain metadata only.
    func testCurrentServerRetainsFlagDetailsAndUsesInjectedClock() throws {
        let doctor = try Doctor.parse([])
        let process = MCPProcessSnapshot(pid: 21, startedAt: instant(20), serverVersion: AppVersion.current,
                                         minimumSeverity: "medium", auditLog: "/tmp/fixture-audit.log")
        let rows = doctor.checkMCPProcesses(processList: { [process] }, binaryModifiedAt: { self.instant(20) },
                                           clock: { self.instant(80) })
        XCTAssertEqual(rows[0].status, "ok")
        XCTAssertEqual(rows[1].status, "info")
        XCTAssertTrue(rows[1].detail.contains("min-severity=medium, audit-log=/tmp/fixture-audit.log"))
        XCTAssertTrue(rows[1].detail.contains("age-seconds=60"))
    }

    // WO-671@v2: missing process metadata is a warning, not evidence of a current server.
    func testUnknownStartAndVersionDoNotClaimFreshness() throws {
        let doctor = try Doctor.parse([])
        let rows = doctor.checkMCPProcesses(processList: { [MCPProcessSnapshot(pid: 22, startedAt: nil)] },
                                           binaryModifiedAt: { self.instant(20) }, clock: { self.instant(80) })
        XCTAssertEqual(rows[1].status, "warn")
        XCTAssertTrue(rows[1].detail.contains("freshness cannot be verified"))
        XCTAssertTrue(rows[1].detail.contains("reconnect MCP"))
    }

    // WO-671@v2: a failed inventory cannot silently masquerade as an empty process list.
    func testUnavailableProcessInventoryWarns() throws {
        let doctor = try Doctor.parse([])
        let rows = doctor.checkMCPProcesses(processList: { throw POSIXError(.EPERM) },
                                           binaryModifiedAt: { self.instant(20) }, clock: { self.instant(80) })
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].status, "warn")
        XCTAssertTrue(rows[0].detail.contains("unable to inspect"))
        XCTAssertFalse(rows[0].detail.contains("no MCP"))
    }

    // WO-671@v2: an empty injected inventory remains informational and never fabricates stale PIDs.
    func testNoServerProcessesRemainsInformational() throws {
        let doctor = try Doctor.parse([])
        let rows = doctor.checkMCPProcesses(processList: { [] }, binaryModifiedAt: { self.instant(20) },
                                           clock: { self.instant(80) })
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].status, "info")
        XCTAssertEqual(rows[0].detail, "no MCP server processes found")
    }

    // WO-671@v2: portable ps dates tolerate padded days and only match an executable/subcommand pair.
    func testProcessSnapshotParsingExcludesShellLookalikes() throws {
        let doctor = try Doctor.parse([])
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
        let prefix = " 31 Mon Oct  5 06:30:00 2026 "
        let snapshot = try XCTUnwrap(doctor.parseMCPProcess(
            prefix + "/opt/pastewatch-cli mcp --min-severity medium --audit-log /tmp/fixture.log", dateFormatter: formatter
        ))
        XCTAssertEqual(snapshot.pid, 31)
        XCTAssertEqual(snapshot.startedAt, formatter.date(from: "Mon Oct 5 06:30:00 2026"))
        XCTAssertEqual(snapshot.minimumSeverity, "medium")
        XCTAssertEqual(snapshot.auditLog, "/tmp/fixture.log")
        XCTAssertNil(snapshot.serverVersion)
        XCTAssertNotNil(doctor.parseMCPProcess(prefix + "/build/PastewatchCLI mcp", dateFormatter: formatter))
        for command in ["/bin/sh -c pastewatch-cli mcp", "/opt/pastewatch-cli doctor", "/opt/other mcp"] {
            XCTAssertNil(doctor.parseMCPProcess(prefix + command, dateFormatter: formatter))
        }
    }

    // WO-671@v2: timestamp fixtures are independent of host load, locale and installed binary age.
    private func instant(_ seconds: TimeInterval) -> Date {
        Date(timeIntervalSince1970: seconds)
    }
}
