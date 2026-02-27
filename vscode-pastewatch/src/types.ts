export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  type: string;
  value: string;
  severity: Severity;
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
