/**
 * GuardRail VS Code / Cursor extension (thin client).
 * Invokes: python -m guardrail via child_process and surfaces diagnostics.
 */
const vscode = require("vscode");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

function runPythonJson(args, envExtra = {}) {
  const cfg = vscode.workspace.getConfiguration("guardrail");
  const py = cfg.get("pythonPath") || "python";
  const modulePath = cfg.get("modulePath") || "";
  const env = { ...process.env, ...envExtra };
  if (modulePath) {
    env.PYTHONPATH = modulePath + path.delimiter + (env.PYTHONPATH || "");
  }
  return new Promise((resolve, reject) => {
    const proc = spawn(py, args, { env });
    let out = "";
    let err = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));
    proc.on("close", (code) => {
      if (!out.trim()) {
        reject(new Error(err || `exit ${code}`));
        return;
      }
      try {
        // last JSON object in output
        const start = out.indexOf("{");
        resolve(JSON.parse(out.slice(start)));
      } catch (e) {
        reject(new Error(`parse failed: ${e.message}\n${out}\n${err}`));
      }
    });
  });
}

function severityToVs(sev) {
  const s = (sev || "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return vscode.DiagnosticSeverity.Error;
  if (s === "MEDIUM") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

/** @type {vscode.DiagnosticCollection} */
let diagnostics;

async function scanFile(uri) {
  const doc = uri
    ? await vscode.workspace.openTextDocument(uri)
    : vscode.window.activeTextEditor?.document;
  if (!doc) {
    vscode.window.showWarningMessage("No active file");
    return;
  }
  const text = doc.getText();
  const tmp = path.join(require("os").tmpdir(), `guardrail-scan-${Date.now()}.py`);
  // write generic temp content
  fs.writeFileSync(tmp, text, "utf8");
  try {
    const code = `
import json,sys
from guardrail.hybrid_scan import hybrid_scan
src=open(${JSON.stringify(tmp)},encoding='utf-8').read()
print(json.dumps(hybrid_scan(src, filename=${JSON.stringify(doc.fileName)})))
`;
    const result = await runPythonJson(["-c", code]);
    const diags = [];
    for (const iss of result.issues || []) {
      const line = Math.max(0, (iss.line || 1) - 1);
      const range = new vscode.Range(line, 0, line, 200);
      const d = new vscode.Diagnostic(
        range,
        `[${iss.rule_id}] ${iss.vulnerability_name || iss.description}`,
        severityToVs(iss.severity)
      );
      d.source = "guardrail";
      d.code = iss.rule_id;
      diags.push(d);
    }
    diagnostics.set(doc.uri, diags);
    vscode.window.showInformationMessage(
      `GuardRail: ${result.issue_count || 0} issue(s), score ${result.risk_score}, ${result.security_verdict}`
    );
  } catch (e) {
    vscode.window.showErrorMessage(`GuardRail scan failed: ${e.message}`);
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch (_) {}
  }
}

async function scanWorkspace() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showWarningMessage("No workspace folder");
    return;
  }
  const root = folder.uri.fsPath;
  try {
    const code = `
import json
from guardrail.repo_scan import scan_repository
print(json.dumps(scan_repository(${JSON.stringify(root)}, max_files=500)))
`;
    const result = await runPythonJson(["-c", code]);
    vscode.window.showInformationMessage(
      `GuardRail workspace: ${result.files_scanned} files, ${result.issue_count} issues, ${result.security_verdict}`
    );
  } catch (e) {
    vscode.window.showErrorMessage(`GuardRail workspace scan failed: ${e.message}`);
  }
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("guardrail");
  context.subscriptions.push(diagnostics);
  context.subscriptions.push(
    vscode.commands.registerCommand("guardrail.scanFile", () => scanFile())
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("guardrail.scanWorkspace", () => scanWorkspace())
  );
}

function deactivate() {
  if (diagnostics) diagnostics.dispose();
}

module.exports = { activate, deactivate };
