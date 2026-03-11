import type { PipelineResult, Finding, Severity } from '../types.js';

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#2563eb',
  INFO: '#6b7280',
};

const GRADE_COLORS: Record<string, string> = {
  A: '#16a34a',
  B: '#65a30d',
  C: '#ca8a04',
  D: '#ea580c',
  F: '#dc2626',
};

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderFinding(f: Finding): string {
  return `
    <div class="finding" style="border-left: 4px solid ${SEVERITY_COLORS[f.severity]};">
      <div class="finding-header">
        <span class="badge" style="background: ${SEVERITY_COLORS[f.severity]};">${f.severity}</span>
        <strong>${escapeHtml(f.id)}</strong>: ${escapeHtml(f.title)}
      </div>
      <div class="finding-meta">Tool: ${escapeHtml(f.toolName)} | Vector: ${escapeHtml(f.vector)} | Confidence: ${(f.confidence * 100).toFixed(0)}%</div>
      <p>${escapeHtml(f.description)}</p>
      <div class="evidence"><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</div>
      ${f.cveRef ? `<div class="cve"><strong>CVE:</strong> <a href="https://osv.dev/vulnerability/${escapeHtml(f.cveRef)}" target="_blank">${escapeHtml(f.cveRef)}</a></div>` : ''}
      <div class="recommendation"><strong>Recommendation:</strong> ${escapeHtml(f.recommendation)}</div>
    </div>`;
}

export function generateHtmlReport(result: PipelineResult): string {
  const gradeColor = GRADE_COLORS[result.score.grade] || '#6b7280';

  const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const groupedFindings = severityOrder
    .map((sev) => ({
      severity: sev,
      findings: result.findings.filter((f) => f.severity === sev),
    }))
    .filter((g) => g.findings.length > 0);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mcp-vet Security Report — ${escapeHtml(result.serverName)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
  .container { max-width: 900px; margin: 0 auto; padding: 2rem; }
  .header { text-align: center; margin-bottom: 2rem; }
  .header h1 { font-size: 1.5rem; color: #475569; }
  .header .meta { color: #94a3b8; font-size: 0.875rem; margin-top: 0.5rem; }
  .grade-circle { display: inline-flex; align-items: center; justify-content: center; width: 120px; height: 120px; border-radius: 50%; border: 6px solid ${gradeColor}; margin: 1.5rem auto; }
  .grade-circle .grade { font-size: 3rem; font-weight: bold; color: ${gradeColor}; }
  .score-text { font-size: 1.25rem; color: #475569; }
  .auto-fail { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 1rem; margin: 1rem 0; color: #991b1b; }
  .section { margin: 2rem 0; }
  .section h2 { font-size: 1.25rem; color: #334155; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; margin-bottom: 1rem; }
  .finding { background: white; border-radius: 8px; padding: 1rem; margin: 0.75rem 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
  .finding-meta { font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.5rem; }
  .badge { color: white; padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .evidence, .recommendation, .cve { font-size: 0.875rem; color: #64748b; margin: 0.5rem 0; padding: 0.5rem; background: #f1f5f9; border-radius: 4px; }
  .summary { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-top: 1rem; }
  .summary-item { text-align: center; }
  .summary-item .count { font-size: 1.5rem; font-weight: bold; }
  .footer { text-align: center; color: #94a3b8; font-size: 0.75rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e2e8f0; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>mcp-vet Security Report</h1>
    <div class="meta">${escapeHtml(result.serverName)} v${escapeHtml(result.serverVersion)} | ${result.scanTimestamp}</div>
    <div class="grade-circle"><span class="grade">${result.score.grade}</span></div>
    <div class="score-text">Trust Score: ${result.score.score}/100</div>
  </div>

  ${result.score.autoFail ? `<div class="auto-fail"><strong>AUTO-FAIL:</strong> ${result.score.autoFailReasons.map(escapeHtml).join('; ')}</div>` : ''}

  <div class="section">
    <h2>Findings (${result.findings.length})</h2>
    ${result.findings.length === 0 ? '<p style="color: #16a34a;">No security issues found.</p>' : ''}
    ${groupedFindings.map((g) => `
      <h3 style="color: ${SEVERITY_COLORS[g.severity]}; margin: 1rem 0 0.5rem;">${g.severity} (${g.findings.length})</h3>
      ${g.findings.map(renderFinding).join('')}
    `).join('')}
  </div>

  <div class="section">
    <div class="summary">
      <h2>Summary</h2>
      <div class="summary-grid">
        ${severityOrder.map((sev) => {
          const count = result.findings.filter((f) => f.severity === sev).length;
          return `<div class="summary-item"><div class="count" style="color: ${SEVERITY_COLORS[sev]};">${count}</div><div>${sev}</div></div>`;
        }).join('')}
      </div>
    </div>
  </div>

  <div class="footer">
    Generated by mcp-vet v0.1.0 | ${result.scanTimestamp}
  </div>
</div>
</body>
</html>`;
}
