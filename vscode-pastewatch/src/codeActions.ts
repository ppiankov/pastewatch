import * as vscode from "vscode";
import * as path from "path";

import { isDiagnosticWithData } from "./diagnostics";

const DIAGNOSTIC_SOURCE = "pastewatch";

export class PastewatchCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== DIAGNOSTIC_SOURCE) continue;

      actions.push(this.createInlineAllowAction(document, diag));

      if (isDiagnosticWithData(diag)) {
        actions.push(this.createAllowlistAction(document, diag));
      }
    }

    return actions;
  }

  private createInlineAllowAction(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      "Add inline pastewatch:allow",
      vscode.CodeActionKind.QuickFix,
    );
    action.diagnostics = [diag];

    const line = document.lineAt(diag.range.start.line);
    const edit = new vscode.WorkspaceEdit();
    const insertPos = line.range.end;
    edit.insert(document.uri, insertPos, " // pastewatch:allow");

    action.edit = edit;
    return action;
  }

  private createAllowlistAction(
    document: vscode.TextDocument,
    diag: vscode.Diagnostic,
  ): vscode.CodeAction {
    if (!isDiagnosticWithData(diag)) {
      return new vscode.CodeAction(
        "Add to .pastewatch-allow",
        vscode.CodeActionKind.QuickFix,
      );
    }

    const action = new vscode.CodeAction(
      "Add to .pastewatch-allow",
      vscode.CodeActionKind.QuickFix,
    );
    action.diagnostics = [diag];
    action.command = {
      command: "pastewatch.addToAllowlist",
      title: "Add to allowlist",
      arguments: [diag.data.finding.value],
    };

    return action;
  }
}

export async function addToAllowlist(value: string): Promise<void> {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage("No workspace folder open.");
    return;
  }

  const allowlistPath = path.join(
    workspaceFolder.uri.fsPath,
    ".pastewatch-allow",
  );
  const uri = vscode.Uri.file(allowlistPath);

  let existing = "";
  try {
    const content = await vscode.workspace.fs.readFile(uri);
    existing = Buffer.from(content).toString("utf8");
  } catch {
    // file doesn't exist yet
  }

  const entry = value.trim();
  if (existing.split("\n").some((line) => line.trim() === entry)) {
    vscode.window.showInformationMessage("Value already in allowlist.");
    return;
  }

  const newContent = existing.endsWith("\n")
    ? existing + entry + "\n"
    : existing === ""
      ? entry + "\n"
      : existing + "\n" + entry + "\n";

  await vscode.workspace.fs.writeFile(uri, Buffer.from(newContent, "utf8"));
  vscode.window.showInformationMessage(`Added to .pastewatch-allow: ${entry}`);
}
