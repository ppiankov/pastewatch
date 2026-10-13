export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  type: string;
  value: string;
  severity: Severity;
  // WO-682@v2: older CLI output has no eligibility flag and must not offer exemptions.
  projectExemptible?: boolean;
}

export interface ScanOutput {
  findings: Finding[];
  count: number;
  obfuscated: string | null;
}

export interface PastewatchConfig {
  autoRefresh: boolean;
  binaryPath: string;
  debounceMs: number;
  failOnSeverity: Severity;
}
