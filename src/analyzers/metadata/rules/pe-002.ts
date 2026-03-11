import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

interface DangerousCombo {
  tools: [RegExp, RegExp];
  risk: string;
  cve?: string;
}

const DANGEROUS_COMBOS: DangerousCombo[] = [
  {
    tools: [/\bgit[_-]|clone/i, /^(read_file|write_file|edit_file|filesystem|file_system|list_directory|create_directory|move_file|delete_file)/i],
    risk: 'Git + Filesystem = potential RCE via git hooks',
    cve: 'CVE-2025-68143',
  },
  {
    tools: [/^(read_file|read_multiple|filesystem|file_system|list_directory|get_file_info)/i, /^(fetch|http_|curl_|wget_)/i],
    risk: 'File read + HTTP out = data exfiltration',
  },
  {
    tools: [/database|query|sql/i, /^(fetch|http_|curl_|send_|email|smtp)/i],
    risk: 'Database access + external communication = data exfiltration',
  },
  {
    tools: [/^(write_file|filesystem|file_system)/i, /exec|run_command|shell|execute/i],
    risk: 'File write + code execution = arbitrary code execution',
  },
];

registerRule(
  {
    id: 'PE-002',
    name: 'Dangerous Tool Combinations',
    vector: 'PRIVILEGE_ESCALATION',
    severity: 'CRITICAL',
    description:
      'Known toxic pairs in multi-server configs: Git + Filesystem = RCE; Read tool + HTTP tool = exfiltration.',
  },
  (server: ServerDefinition, allServers?: ServerDefinition[]): Finding[] => {
    const findings: Finding[] = [];
    const servers = allServers && allServers.length > 1 ? allServers : [server];

    const allToolNames = servers.flatMap((s) => s.tools.map((t) => t.name));

    for (const combo of DANGEROUS_COMBOS) {
      const hasFirst = allToolNames.some((name) => combo.tools[0].test(name));
      const hasSecond = allToolNames.some((name) => combo.tools[1].test(name));

      if (hasFirst && hasSecond) {
        findings.push({
          id: 'PE-002',
          vector: 'PRIVILEGE_ESCALATION',
          severity: 'CRITICAL',
          title: 'Dangerous Tool Combination',
          description: `${combo.risk}`,
          toolName: server.name,
          evidence: `Matched tool patterns in server configuration`,
          cveRef: combo.cve,
          recommendation:
            'Review whether these tools need to be available in the same configuration. Consider isolating high-risk tools.',
          confidence: 0.75,
        });
      }
    }

    return findings;
  },
);
