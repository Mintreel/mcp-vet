import type { PipelineResult, MultiPipelineResult, Finding, Severity } from '../types.js';

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '\x1b[41m\x1b[37m', // white on red bg
  HIGH: '\x1b[31m', // red
  MEDIUM: '\x1b[33m', // yellow
  LOW: '\x1b[34m', // blue
  INFO: '\x1b[90m', // gray
};

const GRADE_COLORS: Record<string, string> = {
  A: '\x1b[32m', // green
  B: '\x1b[32m', // green
  C: '\x1b[33m', // yellow
  D: '\x1b[33m', // yellow
  F: '\x1b[31m', // red
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';

const BOX_W = 59; // outer width of boxes

function dim(s: string): string {
  return `${DIM}${s}${RESET}`;
}

function headerBox(): string[] {
  const inner = BOX_W - 2;
  const lines: string[] = [];
  lines.push(dim(`┌${'─'.repeat(inner)}┐`));
  lines.push(dim('│') + `  ${BOLD}mcp-vet${RESET} v0.1.0` + ' '.repeat(inner - 17) + dim('│'));
  lines.push(dim('│') + '  MCP Security Audit' + ' '.repeat(inner - 20) + dim('│'));
  lines.push(dim(`└${'─'.repeat(inner)}┘`));
  return lines;
}

function scoreBox(label: string, score: number, grade: string, autoFailReasons?: string[]): string[] {
  const inner = BOX_W - 2;
  const gradeColor = GRADE_COLORS[grade] || '';
  const lines: string[] = [];
  lines.push('');
  lines.push(dim(`╔${'═'.repeat(inner)}╗`));
  lines.push(dim('║') + ' '.repeat(inner) + dim('║'));

  const gradeStr = `Grade: ${gradeColor}${BOLD}${grade}${RESET}`;
  // We pad based on visible chars. Approximate: just pad the right side.
  const visibleLen = `     ${label}: ${score}/100       Grade: ${grade}`.length;
  const pad = inner - visibleLen;
  lines.push(dim('║') + `     ${label}: ${BOLD}${score}/100${RESET}       ${gradeStr}` + ' '.repeat(Math.max(0, pad)) + dim('║'));

  lines.push(dim('║') + ' '.repeat(inner) + dim('║'));

  if (autoFailReasons && autoFailReasons.length > 0) {
    for (const reason of autoFailReasons) {
      const afText = `     ⚠ AUTO-FAIL: ${reason}`;
      const afPad = inner - afText.length;
      lines.push(dim('║') + afText + ' '.repeat(Math.max(0, afPad)) + dim('║'));
    }
    lines.push(dim('║') + ' '.repeat(inner) + dim('║'));
  }

  lines.push(dim(`╚${'═'.repeat(inner)}╝`));
  return lines;
}

function severityLabel(severity: Severity): string {
  return `${SEVERITY_COLORS[severity]}${severity}${RESET}`;
}

function summaryLine(findings: Finding[]): string {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.severity]++;
  const parts = SEVERITY_ORDER.map((s) => `${counts[s]} ${s.toLowerCase()}`);
  return `  Summary: ${parts.join(' · ')}`;
}

function separator(): string {
  return `  ${'─'.repeat(BOX_W - 2)}`;
}

function formatFinding(f: Finding): string[] {
  const lines: string[] = [];
  lines.push(`  ${severityLabel(f.severity)}  ${BOLD}${f.id}${RESET}  ${f.title}`);
  if (f.toolName) {
    // Use "Server:" for server-level, "Tool:" for tool-level
    const label = f.toolName.startsWith('@') || f.toolName.includes('/') ? 'Server' : 'Tool';
    lines.push(`  ├─ ${label}: ${f.toolName}`);
  }
  lines.push(`  ├─ ${f.description}`);
  if (f.evidence) {
    lines.push(`  ├─ Evidence: ${f.evidence}`);
  }
  lines.push(`  └─ Fix: ${f.recommendation}`);
  return lines;
}

export function formatTerminalReport(result: PipelineResult): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(...headerBox());
  lines.push('');

  // Server info
  lines.push(`  Server     ${result.serverName}`);
  lines.push(`  Version    ${result.serverVersion}`);
  if (result.toolCount != null) {
    lines.push(`  Tools      ${result.toolCount} scanned`);
  }
  if (result.connectionStatus) {
    if (result.connectionStatus === 'connected') {
      lines.push(`  Connection ${GREEN}✓ live (stdio)${RESET}`);
    } else if (result.connectionStatus === 'failed') {
      lines.push(`  Connection ${YELLOW}✗ failed${RESET}`);
    } else if (result.connectionStatus === 'skipped') {
      lines.push(`  Connection ${dim('— skipped')}`);
    }
  }
  lines.push(`  Scanned    just now`);

  const notScanned = result.connectionStatus === 'failed' && (result.toolCount ?? 0) === 0;

  if (notScanned) {
    // Connection failed, no tools were scanned — don't show a score
    lines.push('');
    lines.push(separator());
    lines.push('');
    lines.push(`  ${YELLOW}⚠ Could not connect — no tools were scanned.${RESET}`);
    const errorMsg = result.connectionErrorMessage || result.connectionError;
    if (errorMsg) {
      lines.push(`  ${errorMsg}`);
    }
    lines.push('');
    lines.push(separator());
  } else {
    // Score box
    lines.push(
      ...scoreBox(
        'Trust Score',
        result.score.score,
        result.score.grade,
        result.score.autoFail ? result.score.autoFailReasons : undefined,
      ),
    );
    lines.push('');

    // Findings
    if (result.findings.length === 0) {
      lines.push(`  ${GREEN}✓ No security issues found.${RESET}`);
      lines.push('');
      lines.push(separator());
      lines.push(summaryLine(result.findings));
    } else {
      lines.push(`  Findings (${result.findings.length})`);
      lines.push(separator());
      lines.push('');

      for (const f of result.findings) {
        lines.push(...formatFinding(f));
        lines.push('');
      }

      lines.push(separator());
      lines.push(summaryLine(result.findings));
    }
  }

  lines.push('');
  return lines.join('\n');
}

export function formatMultiServerReport(result: MultiPipelineResult): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(...headerBox());
  lines.push('');

  // Configs
  lines.push(`  Configs    ${result.discoveredConfigs.length} files discovered`);
  for (const cfg of result.discoveredConfigs) {
    lines.push(`             ${cfg}`);
  }
  lines.push('');
  lines.push(`  Servers    ${result.results.length} found`);
  lines.push('');
  lines.push(separator());
  lines.push('');

  // Per-server lines
  for (const r of result.results) {
    const gradeColor = GRADE_COLORS[r.score.grade] || '';
    const isFailed = r.connectionStatus === 'failed';
    const isSkipped = r.connectionStatus === 'skipped';

    if (isFailed) {
      lines.push(`  ${dim('?')}  ${dim('--')}  ${YELLOW}✗${RESET} ${r.serverName}${' '.repeat(Math.max(1, 21 - r.serverName.length))}${dim('connection failed')}`);
    } else if (isSkipped) {
      const findingCount = r.findings.length;
      const findingLabel = findingCount === 1 ? 'finding' : 'findings';
      lines.push(`  ${gradeColor}${BOLD}${r.score.grade}${RESET}  ${r.score.score.toString().padStart(2)}  ${dim('—')} ${r.serverName}${' '.repeat(Math.max(1, 21 - r.serverName.length))}${dim(`${findingCount} ${findingLabel}`)}`);
    } else {
      // connected or no status
      const findingCount = r.findings.length;
      const findingLabel = findingCount === 1 ? 'finding' : 'findings';
      const toolStr = r.toolCount != null ? `${dim(`${r.toolCount} tools`)}   ` : '';
      lines.push(`  ${gradeColor}${BOLD}${r.score.grade}${RESET}  ${r.score.score.toString().padStart(2)}  ${GREEN}✓${RESET} ${r.serverName}${' '.repeat(Math.max(1, 21 - r.serverName.length))}${toolStr}${dim(`${findingCount} ${findingLabel}`)}`);
    }
  }

  lines.push('');
  lines.push(separator());

  // Combined score box
  lines.push(
    ...scoreBox(
      'Combined Score',
      result.combinedScore.score,
      result.combinedScore.grade,
      result.combinedScore.autoFail ? result.combinedScore.autoFailReasons : undefined,
    ),
  );
  lines.push('');

  // Cross-server findings
  const crossFindings = result.combinedFindings.filter(
    (f) => f.vector === 'CROSS_SERVER_SHADOWING',
  );
  if (crossFindings.length > 0) {
    lines.push('  Cross-Server Analysis');
    lines.push(separator());
    lines.push('');
    for (const f of crossFindings) {
      lines.push(...formatFinding(f));
      lines.push('');
    }
  }

  // Summary
  if (result.combinedFindings.length === 0) {
    lines.push(`  ${GREEN}✓ No security issues found.${RESET}`);
    lines.push('');
    lines.push(separator());
    lines.push(summaryLine(result.combinedFindings));
  } else {
    lines.push(separator());
    lines.push(summaryLine(result.combinedFindings));
  }

  // Errors section
  const errorServers = result.results.filter((r) => r.connectionError);
  if (errorServers.length > 0) {
    lines.push('');
    lines.push('  Errors');
    lines.push(separator());
    lines.push('');
    for (const r of errorServers) {
      const errorMsg = r.connectionErrorMessage || r.connectionError;
      lines.push(`  ${YELLOW}✗${RESET} ${r.serverName} — ${errorMsg}`);
      lines.push('');
    }
  }

  lines.push('');
  return lines.join('\n');
}
