import type { Finding, ServerDefinition } from '../../../types.js';
import { registerRule } from '../rule-registry.js';

const FILE_PATH_PARAM_PATTERNS = [
  /^file[_-]?path$/i,
  /^filepath$/i,
  /^path$/i,
  /^filename$/i,
  /^file$/i,
  /^directory$/i,
  /^dir$/i,
  /^folder$/i,
];

// Tool names where file path params are expected
const FILE_TOOL_PATTERNS = [
  /file/i,
  /read/i,
  /write/i,
  /dir/i,
  /folder/i,
  /upload/i,
  /download/i,
  /fs/i,
  /filesystem/i,
];

// Tool name prefixes where path parameters are inherently expected
const PATH_EXPECTED_PREFIXES = [
  /^git[_-]/i,
  /^kubectl[_-]/i,
  /^docker[_-]/i,
  /^browser[_-]/i,
  /^file[_-]/i,
  /^fs[_-]/i,
  /^directory[_-]/i,
  /^repo[_-]/i,
];

registerRule(
  {
    id: 'DE-003',
    name: 'Broad File Path Parameters',
    vector: 'DATA_EXFILTRATION',
    severity: 'MEDIUM',
    description: 'Non-file tools with parameters accepting arbitrary file paths.',
  },
  (server: ServerDefinition): Finding[] => {
    const findings: Finding[] = [];

    for (const tool of server.tools) {
      const isFileTool = FILE_TOOL_PATTERNS.some((p) => p.test(tool.name));
      if (isFileTool) continue;
      const isPathExpected = PATH_EXPECTED_PREFIXES.some((p) => p.test(tool.name));
      if (isPathExpected) continue;

      for (const param of tool.parameters) {
        const isFileParam = FILE_PATH_PARAM_PATTERNS.some((p) => p.test(param.name));
        if (isFileParam) {
          findings.push({
            id: 'DE-003',
            vector: 'DATA_EXFILTRATION',
            severity: 'MEDIUM',
            title: 'Broad File Path Parameter',
            description: `Tool "${tool.name}" accepts file path parameter "${param.name}" but is not a file-related tool.`,
            toolName: tool.name,
            evidence: `Parameter "${param.name}" in non-file tool "${tool.name}"`,
            recommendation:
              'Review why a non-file tool needs file path parameters. This could allow arbitrary file access.',
            confidence: 0.6,
          });
        }
      }
    }

    return findings;
  },
);
