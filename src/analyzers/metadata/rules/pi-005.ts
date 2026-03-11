import type { Finding, Severity, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

// Injection signal patterns from other PI rules — used to escalate severity
const INJECTION_SIGNALS = [
  // PI-001: Instruction override keywords
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i,
  /forget\s+(all\s+)?(previous|prior|above|earlier)/i,
  /disregard\s+(all\s+)?(previous|prior|above|earlier)/i,
  /override\s+(all\s+)?(previous|prior|system)/i,
  /you\s+are\s+now\s+/i,
  /new\s+instructions?\s*:/i,
  /system\s*:\s*/i,
  /<\s*(?:IMPORTANT|SYSTEM|instructions?|override|context)\s*>/i,
  // PI-002: Secrecy directives
  /do\s+not\s+(mention|tell|reveal|disclose|show|display|inform)/i,
  /don'?t\s+(mention|tell|reveal|disclose|show|display|inform)/i,
  /without\s+(notifying|telling|informing|alerting)/i,
  /keep\s+(this|it)\s+(secret|hidden|private|between\s+us)/i,
  /never\s+(reveal|mention|disclose|tell)/i,
  // PI-003: Sensitive file paths
  /~\/.ssh/i,
  /~\/.aws/i,
  /~\/.gnupg/i,
  /id_rsa/i,
  /private[_-]?key/i,
  // PI-004: Invisible Unicode
  /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/,
  /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/,
  // PI-007: Identity injection
  /your\s+(role|purpose|mission|goal)\s*(is|:)/i,
  /act\s+as\s+(a|an|the)/i,
  // PI-008: Tool redirect
  /instead\s+(of\s+this|use|call|invoke)/i,
  /always\s+(use|prefer|call)\s+/i,
];

function hasInjectionSignals(text: string): boolean {
  return INJECTION_SIGNALS.some((p) => p.test(text));
}

registerRule(
  {
    id: 'PI-005',
    name: 'Description Length Anomaly',
    vector: 'PROMPT_INJECTION',
    severity: 'MEDIUM',
    description:
      'Unusually long descriptions may hide instructions. Escalates only if other injection signals are present.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const len = tool.description.length;

      if (len <= 1500) continue;

      const hasSignals = hasInjectionSignals(tool.description);

      let severity: Severity;
      let confidence: number;

      if (hasSignals && len > 10000) {
        severity = 'CRITICAL';
        confidence = 0.8;
      } else if (hasSignals && len > 5000) {
        severity = 'HIGH';
        confidence = 0.7;
      } else if (len > 10000) {
        // Very long but no injection signals — still notable
        severity = 'HIGH';
        confidence = 0.5;
      } else if (len > 5000) {
        severity = 'MEDIUM';
        confidence = 0.4;
      } else {
        // 1501–5000 chars, no injection signals
        severity = hasSignals ? 'MEDIUM' : 'LOW';
        confidence = hasSignals ? 0.5 : 0.3;
      }

      findings.push({
        id: 'PI-005',
        vector: 'PROMPT_INJECTION',
        severity,
        title: 'Description Length Anomaly',
        description: `Tool "${tool.name}" has an unusually long description (${len} characters).${hasSignals ? ' Injection patterns were also detected.' : ' No injection patterns detected — may be a legitimately complex tool.'}`,
        toolName: tool.name,
        evidence: `Description length: ${len} characters${hasSignals ? ' (with injection signals)' : ''}`,
        recommendation: hasSignals
          ? 'Review the full tool description for hidden instructions. The combination of length and injection patterns is suspicious.'
          : 'Review the tool description. Long descriptions are not inherently malicious but can be used to hide instructions.',
        confidence,
      });
    }

    return findings;
  },
);
