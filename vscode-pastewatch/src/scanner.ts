import { execFile, ExecFileException } from "child_process";
import * as vscode from "vscode";

import { PastewatchConfig, ScanOutput } from "./types";

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export function loadConfig(): PastewatchConfig {
  const cfg = vscode.workspace.getConfiguration("pastewatch");
  return {
    autoRefresh: cfg.get<boolean>("autoRefresh", true),
    binaryPath: cfg.get<string>("binaryPath", "pastewatch-cli"),
    debounceMs: cfg.get<number>("debounceMs", 500),
    failOnSeverity: cfg.get<string>("failOnSeverity", "low") as PastewatchConfig["failOnSeverity"],
  };
}

export async function runScan(
  filePath: string,
  config: PastewatchConfig,
  output: vscode.OutputChannel,
): Promise<ScanOutput> {
  const args = ["scan", "--format", "json", "--file", filePath, "--fail-on-severity", config.failOnSeverity];

  output.appendLine(`pastewatch-cli ${args.join(" ")}`);

  const result = await runCommand(config.binaryPath, args);

  if (result.stderr.trim() !== "") {
    output.appendLine(`stderr: ${result.stderr.trim()}`);
  }

  if (result.stdout.trim() === "") {
    return { findings: [], count: 0, obfuscated: null };
  }

  let scanOutput: ScanOutput;
  try {
    scanOutput = JSON.parse(result.stdout) as ScanOutput;
  } catch (err) {
    throw new Error(`invalid JSON from pastewatch-cli: ${String(err)}`);
  }

  if (!Array.isArray(scanOutput.findings)) {
    throw new Error("unexpected pastewatch-cli output schema");
  }

  return scanOutput;
}

function runCommand(binary: string, args: string[]): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      args,
      { maxBuffer: 10 * 1024 * 1024, env: process.env },
      (error, stdout, stderr) => {
        const execErr = error as ExecFileException | null;

        if (execErr && isBinaryMissing(execErr)) {
          reject(new Error(`pastewatch-cli not found: ${binary}. Install it with: brew install ppiankov/tap/pastewatch-cli`));
          return;
        }

        // pastewatch-cli exits non-zero (6) when findings exist — that's expected
        if (execErr && stdout.trim() === "") {
          const detail = stderr.trim() || execErr.message;
          reject(new Error(detail));
          return;
        }

        resolve({
          stdout,
          stderr,
          exitCode: typeof execErr?.code === "number" ? execErr.code : 0,
        });
      },
    );
  });
}

function isBinaryMissing(err: ExecFileException): boolean {
  return err.code === "ENOENT" || /ENOENT/.test(err.message);
}
