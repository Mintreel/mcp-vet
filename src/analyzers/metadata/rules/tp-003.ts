import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

// Patterns suggesting dynamic or versioned content
const VERSION_MARKERS = /\b(?:v\d+\s*:|updated\s*:|new\s+version\s*:|latest\s*:|changed\s*:)/i;

// Patterns suggesting remote configuration loading
const REMOTE_CONFIG_PATTERNS = /\b(?:config\s+from|loaded\s+from|fetched\s+from)\b/i;

// Template-like placeholders
const TEMPLATE_PLACEHOLDERS = /(?:\{\{.+?\}\}|\$\{.+?\}|%s|\{0\})/;

registerRule(
  {
    id: 'TP-003',
    name: 'Description Version Diffing Risk',
    vector: 'TOOL_POISONING',
    severity: 'INFO',
    description:
      'Tool description contains markers suggesting dynamic or versioned content that may change between scans.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const desc = tool.description;
      if (!desc) continue;

      // Check for version/update markers
      const versionMatch = desc.match(VERSION_MARKERS);
      if (versionMatch) {
        findings.push({
          id: 'TP-003',
          vector: 'TOOL_POISONING',
          severity: 'INFO',
          title: 'Description Version Diffing Risk',
          description: `Tool "${tool.name}" description contains version/update markers suggesting dynamic content.`,
          toolName: tool.name,
          evidence: `Version marker found: "${versionMatch[0]}"`,
          recommendation:
            'Review the tool description for signs of dynamic content. Descriptions that change between scans may indicate rug-pull risk.',
          confidence: 0.5,
        });
        continue;
      }

      // Check for remote configuration references
      const remoteMatch = desc.match(REMOTE_CONFIG_PATTERNS);
      if (remoteMatch) {
        findings.push({
          id: 'TP-003',
          vector: 'TOOL_POISONING',
          severity: 'INFO',
          title: 'Description Version Diffing Risk',
          description: `Tool "${tool.name}" description references remote configuration loading.`,
          toolName: tool.name,
          evidence: `Remote config reference found: "${remoteMatch[0]}"`,
          recommendation:
            'Descriptions referencing remote configuration may change dynamically. Verify the tool description is static and trustworthy.',
          confidence: 0.6,
        });
        continue;
      }

      // Check for template placeholders
      const templateMatch = desc.match(TEMPLATE_PLACEHOLDERS);
      if (templateMatch) {
        findings.push({
          id: 'TP-003',
          vector: 'TOOL_POISONING',
          severity: 'INFO',
          title: 'Description Version Diffing Risk',
          description: `Tool "${tool.name}" description contains template-like placeholders.`,
          toolName: tool.name,
          evidence: `Template placeholder found: "${templateMatch[0]}"`,
          recommendation:
            'Template placeholders in tool descriptions suggest the content may be dynamically generated. Verify the description is static.',
          confidence: 0.55,
        });
        continue;
      }
    }

    return findings;
  },
);
