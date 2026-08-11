import * as vscode from 'vscode';
import { scanText, RuleMatch, Severity } from './rules';

const diagnosticCollection = vscode.languages.createDiagnosticCollection('guardtrace');
const SEVERITY_MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH: vscode.DiagnosticSeverity.Error,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  LOW: vscode.DiagnosticSeverity.Information
};
const SEVERITY_ICON: Record<Severity, string> = { CRITICAL: '🔴', HIGH: '🔴', MEDIUM: '🟠', LOW: '🟡' };

// document uri (string) -> findings for that file
const findingsByFile = new Map<string, RuleMatch[]>();

function fingerprint(uri: string, f: RuleMatch): string {
  return `${uri}::${f.ruleId}::${f.line}`;
}

function getEnabledRules(): string[] {
  return vscode.workspace.getConfiguration('guardtrace').get<string[]>('enabledRules', []);
}

function getIgnored(): string[] {
  return vscode.workspace.getConfiguration('guardtrace').get<string[]>('ignoredFindings', []);
}

function scanDocument(doc: vscode.TextDocument, dashboard: DashboardProvider, findingsView: FindingsProvider) {
  if (doc.uri.scheme !== 'file') return;
  const text = doc.getText();
  const enabled = getEnabledRules();
  const ignored = new Set(getIgnored());
  const raw = scanText(text, enabled);
  const filtered = raw.filter((f) => !ignored.has(fingerprint(doc.uri.toString(), f)));

  findingsByFile.set(doc.uri.toString(), filtered);

  const diagnostics: vscode.Diagnostic[] = filtered.map((f) => {
    const line = doc.lineAt(Math.min(f.line, doc.lineCount - 1));
    const range = new vscode.Range(f.line, f.startCol, f.line, Math.max(f.endCol, f.startCol + 1));
    const d = new vscode.Diagnostic(range, `${SEVERITY_ICON[f.severity]} ${f.title}: ${f.message}`, SEVERITY_MAP[f.severity]);
    d.source = 'GuardTrace';
    d.code = f.ruleId;
    return d;
  });

  diagnosticCollection.set(doc.uri, diagnostics);
  dashboard.refresh();
  findingsView.refresh();
}

function computeScore(): { score: number; label: string; counts: Record<Severity, number> } {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const findings of findingsByFile.values()) {
    for (const f of findings) counts[f.severity]++;
  }
  const penalty = counts.CRITICAL * 15 + counts.HIGH * 10 + counts.MEDIUM * 4 + counts.LOW * 1;
  const score = Math.max(0, 100 - penalty);
  const label = score >= 90 ? 'EXCELLENT' : score >= 70 ? 'MODERATE' : score >= 40 ? 'AT RISK' : 'CRITICAL';
  return { score, label, counts };
}

class DashboardProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  refresh() { this._onDidChangeTreeData.fire(); }

  getTreeItem(el: vscode.TreeItem) { return el; }

  getChildren(): vscode.TreeItem[] {
    const { score, label, counts } = computeScore();
    const scoreItem = new vscode.TreeItem(`Security Score: ${score}/100 (${label})`);
    scoreItem.iconPath = new vscode.ThemeIcon('shield');
    const items = [
      scoreItem,
      new vscode.TreeItem(`🔴 Critical: ${counts.CRITICAL}`),
      new vscode.TreeItem(`🔴 High: ${counts.HIGH}`),
      new vscode.TreeItem(`🟠 Medium: ${counts.MEDIUM}`),
      new vscode.TreeItem(`🟡 Low: ${counts.LOW}`)
    ];
    return items;
  }
}

class FindingsProvider implements vscode.TreeDataProvider<FindingItem | vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  refresh() { this._onDidChangeTreeData.fire(); }

  getTreeItem(el: vscode.TreeItem) { return el; }

  getChildren(): vscode.TreeItem[] {
    const items: FindingItem[] = [];
    for (const [uriStr, findings] of findingsByFile.entries()) {
      for (const f of findings) {
        items.push(new FindingItem(uriStr, f));
      }
    }
    if (items.length === 0) {
      return [new vscode.TreeItem('No findings 🎉')];
    }
    return items;
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(public readonly uriStr: string, public readonly finding: RuleMatch) {
    super(`${SEVERITY_ICON[finding.severity]} ${finding.title} — ${uriStr.split('/').pop()}:${finding.line + 1}`);
    this.description = finding.message;
    this.command = {
      command: 'vscode.open',
      title: 'Open',
      arguments: [vscode.Uri.parse(uriStr), { selection: new vscode.Range(finding.line, finding.startCol, finding.line, finding.endCol) }]
    };
    this.contextValue = 'guardtraceFinding';
  }
}

class GuardTraceActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(doc: vscode.TextDocument, range: vscode.Range, ctx: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diag of ctx.diagnostics) {
      if (diag.source !== 'GuardTrace') continue;
      const explain = new vscode.CodeAction('GuardTrace: View Explanation', vscode.CodeActionKind.QuickFix);
      explain.command = { command: 'guardtrace.explain', title: 'Explain', arguments: [diag] };
      explain.diagnostics = [diag];
      actions.push(explain);

      const ignore = new vscode.CodeAction('GuardTrace: Ignore This Finding', vscode.CodeActionKind.QuickFix);
      ignore.command = { command: 'guardtrace.ignoreFinding', title: 'Ignore', arguments: [doc, diag] };
      ignore.diagnostics = [diag];
      actions.push(ignore);
    }
    return actions;
  }
}

export function activate(context: vscode.ExtensionContext) {
  const dashboard = new DashboardProvider();
  const findingsView = new FindingsProvider();
  vscode.window.registerTreeDataProvider('guardtrace.dashboard', dashboard);
  vscode.window.registerTreeDataProvider('guardtrace.findings', findingsView);

  context.subscriptions.push(diagnosticCollection);

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, new GuardTraceActionProvider(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
    })
  );

  const rescan = (doc: vscode.TextDocument) => scanDocument(doc, dashboard, findingsView);

  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(rescan));
  context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(rescan));
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => rescan(e.document))
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('guardtrace.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) rescan(editor.document);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('guardtrace.scanWorkspace', async () => {
      const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,java,go,rb,php}',
        '**/node_modules/**',
        500
      );
      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'GuardTrace: scanning workspace...' },
        async (progress) => {
          for (let i = 0; i < files.length; i++) {
            const doc = await vscode.workspace.openTextDocument(files[i]);
            rescan(doc);
            progress.report({ increment: 100 / files.length });
          }
        }
      );
      const { score, counts } = computeScore();
      vscode.window.showInformationMessage(
        `GuardTrace scan complete. Score: ${score}/100 — ${counts.CRITICAL + counts.HIGH} high/critical, ${counts.MEDIUM} medium, ${counts.LOW} low findings.`
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('guardtrace.explain', (diag: vscode.Diagnostic) => {
      vscode.window.showInformationMessage(String(diag.message));
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('guardtrace.ignoreFinding', async (doc: vscode.TextDocument, diag: vscode.Diagnostic) => {
      const findings = findingsByFile.get(doc.uri.toString()) || [];
      const match = findings.find((f) => f.line === diag.range.start.line && f.ruleId === diag.code);
      if (!match) return;
      const fp = fingerprint(doc.uri.toString(), match);
      const cfg = vscode.workspace.getConfiguration('guardtrace');
      const ignored = cfg.get<string[]>('ignoredFindings', []);
      await cfg.update('ignoredFindings', [...ignored, fp], vscode.ConfigurationTarget.Workspace);
      rescan(doc);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('guardtrace.generateReport', async () => {
      const { score, label, counts } = computeScore();
      const byRule = new Map<string, { title: string; severity: Severity; count: number }>();
      for (const findings of findingsByFile.values()) {
        for (const f of findings) {
          const key = f.ruleId;
          const entry = byRule.get(key) || { title: f.title, severity: f.severity, count: 0 };
          entry.count++;
          byRule.set(key, entry);
        }
      }
      const lines: string[] = [];
      lines.push('SECURITY REPORT');
      lines.push('===============');
      lines.push('');
      lines.push(`Project: ${vscode.workspace.name || 'untitled'}`);
      lines.push(`Date: ${new Date().toISOString().slice(0, 10)}`);
      lines.push('');
      lines.push(`Security Score: ${score}/100 (${label})`);
      lines.push('');
      for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]) {
        const rules = [...byRule.entries()].filter(([, v]) => v.severity === sev);
        if (rules.length === 0) continue;
        lines.push(sev);
        lines.push('-'.repeat(sev.length));
        for (const [, v] of rules) {
          lines.push(`${v.title.padEnd(22)} ${v.count}`);
        }
        lines.push('');
      }
      lines.push('Recommendations');
      lines.push('---------------');
      let i = 1;
      if (counts.HIGH || counts.CRITICAL) lines.push(`${i++}. Parameterize SQL queries and validate/escape all external input.`);
      if (byRule.has('hardcoded-secret')) lines.push(`${i++}. Move secrets to environment variables or a secrets manager.`);
      if (byRule.has('weak-crypto')) lines.push(`${i++}. Replace MD5/SHA1 with SHA-256, and use bcrypt/Argon2 for passwords.`);
      if (byRule.has('insecure-http')) lines.push(`${i++}. Switch insecure HTTP endpoints to HTTPS.`);
      if (i === 1) lines.push('1. No major issues found — keep scanning on every change.');

      const doc = await vscode.workspace.openTextDocument({ content: lines.join('\n'), language: 'plaintext' });
      await vscode.window.showTextDocument(doc, { preview: false });
    })
  );

  // initial scan of already-open documents
  vscode.workspace.textDocuments.forEach(rescan);
}

export function deactivate() {
  diagnosticCollection.clear();
  diagnosticCollection.dispose();
}
