import type { PipelineResult } from '../types.js';

export function formatJsonReport(result: PipelineResult): string {
  return JSON.stringify(
    {
      serverName: result.serverName,
      serverVersion: result.serverVersion,
      score: result.score.score,
      grade: result.score.grade,
      autoFail: result.score.autoFail,
      autoFailReasons: result.score.autoFailReasons,
      findings: result.findings.map((f) => ({
        id: f.id,
        vector: f.vector,
        severity: f.severity,
        title: f.title,
        description: f.description,
        toolName: f.toolName,
        evidence: f.evidence,
        cveRef: f.cveRef,
        recommendation: f.recommendation,
        confidence: f.confidence,
      })),
      scanTimestamp: result.scanTimestamp,
      mcpVetVersion: '0.1.0',
    },
    null,
    2,
  );
}
