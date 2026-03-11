import type { Finding, ServerDefinition, Severity } from '../../types.js';

interface OsvVulnerability {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
}

interface OsvResponse {
  vulns?: OsvVulnerability[];
}

async function queryOsv(
  packageName: string,
  version: string,
  ecosystem: string,
): Promise<OsvResponse | null> {
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        package: { name: packageName, ecosystem },
        version,
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return null;
    return (await res.json()) as OsvResponse;
  } catch {
    return null;
  }
}

function cvssToSeverity(score: number): Severity {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'INFO';
}

export async function runSU001(server: ServerDefinition): Promise<Finding[]> {
  const findings: Finding[] = [];
  const pkg = server.packageInfo;
  if (!pkg) return findings;

  const ecosystem = pkg.registry === 'pypi' ? 'PyPI' : 'npm';
  const response = await queryOsv(pkg.name, pkg.version, ecosystem);

  if (response === null) {
    findings.push({
      id: 'SU-001',
      vector: 'SUPPLY_CHAIN',
      severity: 'INFO',
      title: 'CVE Check Skipped',
      description: `Could not reach OSV.dev to check for known vulnerabilities in ${pkg.name}@${pkg.version}.`,
      toolName: server.name,
      evidence: 'OSV.dev API unreachable',
      recommendation: 'Retry with network access or check manually at https://osv.dev',
      confidence: 0.5,
    });
    return findings;
  }

  if (response.vulns && response.vulns.length > 0) {
    for (const vuln of response.vulns) {
      let cvssScore = 0;
      let severity: Severity = 'HIGH';

      if (vuln.severity) {
        for (const s of vuln.severity) {
          if (s.type === 'CVSS_V3') {
            cvssScore = parseFloat(s.score) || 0;
            severity = cvssToSeverity(cvssScore);
            break;
          }
        }
      }

      findings.push({
        id: 'SU-001',
        vector: 'SUPPLY_CHAIN',
        severity,
        title: 'Known CVE',
        description: `${pkg.name}@${pkg.version} has known vulnerability: ${vuln.id}${vuln.summary ? ` — ${vuln.summary}` : ''}`,
        toolName: server.name,
        evidence: `${vuln.id}${cvssScore ? ` (CVSS: ${cvssScore})` : ''}`,
        cveRef: vuln.id,
        recommendation: `Update ${pkg.name} to a patched version. See https://osv.dev/vulnerability/${vuln.id}`,
        confidence: 1.0,
      });
    }
  }

  return findings;
}
