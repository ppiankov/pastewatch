import * as vscode from "vscode";

import { Finding, Severity } from "./types";

const DIAGNOSTIC_SOURCE = "pastewatch";

export function buildDiagnostics(
  findings: Finding[],
  document: vscode.TextDocument,
): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];
  const text = document.getText();

  for (const finding of findings) {
    const range = findRange(finding.value, text, document);
    if (!range) continue;

    const diag = new vscode.Diagnostic(
      range,
      `${finding.type}: secret detected (${finding.severity})`,
      mapSeverity(finding.severity),
    );
    diag.source = DIAGNOSTIC_SOURCE;
    (diag as DiagnosticWithData).data = { finding };
    diagnostics.push(diag);
  }

  return diagnostics;
}

export interface DiagnosticWithData extends vscode.Diagnostic {
  data: { finding: Finding };
}

export function isDiagnosticWithData(
  diag: vscode.Diagnostic,
): diag is DiagnosticWithData {
  const d = diag as DiagnosticWithData;
  return d.data != null && d.data.finding != null;
}

function mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
  }
}

function findRange(
  value: string,
  text: string,
  document: vscode.TextDocument,
): vscode.Range | undefined {
  const idx = text.indexOf(value);
  if (idx === -1) return undefined;

  const start = document.positionAt(idx);
  const end = document.positionAt(idx + value.length);
  return new vscode.Range(start, end);
}
