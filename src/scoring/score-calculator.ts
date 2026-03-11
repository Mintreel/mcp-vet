import type { Finding, TrustScore, Severity, AttackVector } from '../types.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

const VECTOR_WEIGHTS: Record<AttackVector, number> = {
  PROMPT_INJECTION: 1.0,
  CROSS_SERVER_SHADOWING: 0.85,
  IMPLEMENTATION_VULN: 0.8,
  TOOL_POISONING: 0.7,
  DATA_EXFILTRATION: 0.5,
  PRIVILEGE_ESCALATION: 0.3,
  SUPPLY_CHAIN: 0.3,
  DENIAL_OF_WALLET: 0.25,
};

function scoreToGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 50) return 'C';
  if (score >= 25) return 'D';
  return 'F';
}

export function checkAutoFail(findings: Finding[]): string[] {
  const reasons: string[] = [];

  // Any PI-002 (secrecy directive)
  if (findings.some((f) => f.id === 'PI-002')) {
    reasons.push('Secrecy directive detected (PI-002)');
  }

  // Any PI-004 with >50 hidden characters
  const pi004 = findings.filter((f) => f.id === 'PI-004');
  for (const f of pi004) {
    const match = f.evidence.match(/(\d+)\s*hidden/i);
    if (match && parseInt(match[1], 10) > 50) {
      reasons.push('Invisible Unicode with >50 hidden characters (PI-004)');
      break;
    }
  }

  // Any TS-001 with behavioral override
  if (findings.some((f) => f.id === 'TS-001' && f.confidence >= 0.8)) {
    reasons.push('Cross-server behavioral override detected (TS-001)');
  }

  // Any SC-001 with unsanitized input
  if (findings.some((f) => f.id === 'SC-001')) {
    reasons.push('Command injection with unsanitized input (SC-001)');
  }

  // Any SU-001 with CVSS >= 9.0
  const su001 = findings.filter((f) => f.id === 'SU-001');
  for (const f of su001) {
    const match = f.evidence.match(/CVSS[:\s]*(\d+\.?\d*)/i);
    if (match && parseFloat(match[1]) >= 9.0) {
      reasons.push('Known CVE with CVSS >= 9.0 (SU-001)');
      break;
    }
  }

  // 3+ CRITICAL from different vectors
  const criticalVectors = new Set(
    findings.filter((f) => f.severity === 'CRITICAL').map((f) => f.vector),
  );
  if (criticalVectors.size >= 3) {
    reasons.push('3+ CRITICAL findings from different attack vectors');
  }

  return reasons;
}

export function calculateScore(findings: Finding[]): TrustScore {
  const autoFailReasons = checkAutoFail(findings);
  const autoFail = autoFailReasons.length > 0;

  let totalDeduction = 0;
  for (const finding of findings) {
    const severityWeight = SEVERITY_WEIGHTS[finding.severity];
    const vectorWeight = VECTOR_WEIGHTS[finding.vector];
    const deduction = severityWeight * finding.confidence * vectorWeight;
    totalDeduction += deduction;
  }

  const rawScore = Math.max(0, Math.round(100 - totalDeduction));
  const score = autoFail ? Math.min(rawScore, 24) : rawScore;
  const grade = autoFail ? 'F' : scoreToGrade(score);

  return { score, grade, autoFail, autoFailReasons };
}
