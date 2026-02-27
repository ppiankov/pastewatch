import * as vscode from "vscode";

import { isDiagnosticWithData } from "./diagnostics";

const DIAGNOSTIC_SOURCE = "pastewatch";

export class PastewatchHoverProvider implements vscode.HoverProvider {
  constructor(
    private readonly diagnosticCollection: vscode.DiagnosticCollection,
  ) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): vscode.Hover | undefined {
    const diagnostics = this.diagnosticCollection.get(document.uri);
    if (!diagnostics) return undefined;

    for (const diag of diagnostics) {
      if (diag.source !== DIAGNOSTIC_SOURCE) continue;
      if (!diag.range.contains(position)) continue;
      if (!isDiagnosticWithData(diag)) continue;

      const { finding } = diag.data;

      const md = new vscode.MarkdownString();
      md.appendMarkdown(`**pastewatch** — ${finding.type}\n\n`);
      md.appendMarkdown(`**Severity:** \`${finding.severity}\`\n\n`);
      md.appendMarkdown(
        `This value was detected as a potential secret. ` +
          `Use the quick-fix to suppress or add it to the allowlist.`,
      );
      md.isTrusted = true;

      return new vscode.Hover(md, diag.range);
    }

    return undefined;
  }
}
