import Foundation

// WO-637: MCP and diagnostics share the exact read authorization and advisory selection.
public struct MCPReadDecision {
    public let authorized: [DetectedMatch]
    public let reportedAdvisories: [DetectedMatch]

    // WO-637: preserve trusted-file filtering and WO-635 advisories below the MCP threshold.
    public static func evaluate(
        matches: [DetectedMatch], content: String, config: PastewatchConfig,
        minimumSeverity: Severity, filePath: String?
    ) -> MCPReadDecision {
        let decision = GuardDecision.evaluate(
            matches: matches, content: content, config: config,
            contentTrust: .trustedFile, minimumSeverity: minimumSeverity, filePath: filePath
        )
        let partition = partitionMutationMatches(
            decision.reportableMatches, site: .mcpRead, minAdvisorySeverity: minimumSeverity
        )
        return MCPReadDecision(
            authorized: partition.authorized,
            reportedAdvisories: partition.advisory + partition.advisoryBelowThreshold.filter {
                $0.advisory == .documentationPolicy
            }
        )
    }
}
