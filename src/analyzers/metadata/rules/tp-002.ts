import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';
import { SEMANTIC_CATEGORIES } from '../data/semantic-categories.js';

registerRule(
  {
    id: 'TP-002',
    name: 'Name-Description Semantic Mismatch',
    vector: 'TOOL_POISONING',
    severity: 'HIGH',
    description:
      'Keyword-based category classification. A math tool mentioning HTTP/email/payment terms is flagged.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      for (const category of SEMANTIC_CATEGORIES) {
        const nameMatches = category.namePatterns.some((p) => p.test(tool.name));
        if (!nameMatches) continue;

        for (const unexpected of category.unexpectedKeywords) {
          const match = tool.description.match(unexpected);
          if (match) {
            findings.push({
              id: 'TP-002',
              vector: 'TOOL_POISONING',
              severity: 'HIGH',
              title: 'Name-Description Semantic Mismatch',
              description: `Tool "${tool.name}" (category: ${category.label}) has unexpected keywords in its description.`,
              toolName: tool.name,
              evidence: `Tool categorized as "${category.label}" but description contains: "${match[0]}"`,
              recommendation:
                'Review the tool description to ensure it matches the tool stated purpose. Unexpected keywords may indicate tool poisoning.',
              confidence: 0.65,
            });
            break;
          }
        }
      }
    }

    return findings;
  },
);
