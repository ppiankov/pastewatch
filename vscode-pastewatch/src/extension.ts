import * as vscode from "vscode";

import { PastewatchCodeActionProvider, addToAllowlist } from "./codeActions";
import { buildDiagnostics } from "./diagnostics";
import { PastewatchHoverProvider } from "./hover";
import { loadConfig, runScan } from "./scanner";

let debounceTimer: ReturnType<typeof setTimeout> | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("pastewatch");
  const diagnostics = vscode.languages.createDiagnosticCollection("pastewatch");

  // Status bar
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100,
  );
  statusBar.command = "pastewatch.refresh";
  statusBar.tooltip = "Click to refresh pastewatch diagnostics";
  updateStatusBar(statusBar, 0);
  statusBar.show();

  // Hover provider
  const hoverProvider = new PastewatchHoverProvider(diagnostics);
  context.subscriptions.push(
    vscode.languages.registerHoverProvider({ scheme: "file" }, hoverProvider),
  );

  // Code action provider
  const codeActionProvider = new PastewatchCodeActionProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      codeActionProvider,
      { providedCodeActionKinds: PastewatchCodeActionProvider.providedCodeActionKinds },
    ),
  );

  // Command: refresh
  context.subscriptions.push(
    vscode.commands.registerCommand("pastewatch.refresh", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        void scanDocument(editor.document, diagnostics, statusBar, output);
      }
    }),
  );

  // Command: add to allowlist
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "pastewatch.addToAllowlist",
      (value: string) => {
        void addToAllowlist(value).then(() => {
          // Re-scan after allowlist update
          const editor = vscode.window.activeTextEditor;
          if (editor) {
            void scanDocument(editor.document, diagnostics, statusBar, output);
          }
        });
      },
    ),
  );

  // Scan on save (debounced)
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = loadConfig();
      if (!config.autoRefresh) return;

      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        void scanDocument(document, diagnostics, statusBar, output);
      }, config.debounceMs);
    }),
  );

  // Scan when active editor changes
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        updateStatusBar(statusBar, diagnostics.get(editor.document.uri)?.length ?? 0);
      }
    }),
  );

  // Clear diagnostics when file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((document) => {
      diagnostics.delete(document.uri);
    }),
  );

  context.subscriptions.push(output, diagnostics, statusBar);

  // Scan active file on activation
  const activeEditor = vscode.window.activeTextEditor;
  if (activeEditor) {
    void scanDocument(activeEditor.document, diagnostics, statusBar, output);
  }
}

async function scanDocument(
  document: vscode.TextDocument,
  diagnosticCollection: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem,
  output: vscode.OutputChannel,
): Promise<void> {
  if (document.uri.scheme !== "file") return;

  const config = loadConfig();

  try {
    const result = await runScan(document.uri.fsPath, config, output);
    const diags = buildDiagnostics(result.findings, document);
    diagnosticCollection.set(document.uri, diags);
    updateStatusBar(statusBar, diags.length);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    output.appendLine(`error: ${msg}`);
    if (msg.includes("not found")) {
      vscode.window.showWarningMessage(msg);
    }
  }
}

function updateStatusBar(statusBar: vscode.StatusBarItem, count: number): void {
  if (count === 0) {
    statusBar.text = "$(shield) pastewatch: clean";
    statusBar.backgroundColor = undefined;
  } else {
    statusBar.text = `$(warning) pastewatch: ${count} finding${count === 1 ? "" : "s"}`;
    statusBar.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground",
    );
  }
}

export function deactivate(): void {
  if (debounceTimer) clearTimeout(debounceTimer);
}
