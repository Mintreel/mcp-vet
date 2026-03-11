# mcp-vet: Technical Design Document

> **Version 3.0 — March 2026 — CONFIDENTIAL**
> Updated with gap analysis, competitor implementation review, and Claude CLI auto-discovery

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Data Flow](#2-data-flow)
3. [Detection Engine: Rule Specifications](#3-detection-engine-rule-specifications)
   - 3.1 Prompt Injection Detection (8 rules)
   - 3.2 Tool Poisoning & Rug Pull Detection (4 rules)
   - 3.3 Data Exfiltration Detection (3 rules)
   - 3.4 Privilege Escalation Detection (3 rules)
   - 3.5 Denial of Wallet Detection (2 rules)
   - 3.6 Cross-Server Shadowing Detection (3 rules)
   - 3.7 Implementation Vulnerability Detection (4 rules)
   - 3.8 Supply Chain & Credential Hygiene (3 rules)
4. [Trust Scoring Model](#4-trust-scoring-model)
5. [Claude CLI Auto-Discovery](#5-claude-cli-auto-discovery) — NEW
6. [Report Generation & Output Formats](#6-report-generation--output-formats)
7. [CLI Interface Design](#7-cli-interface-design)
8. [Competitive Analysis](#8-competitive-analysis) — UPDATED
9. [Extension Points for v2](#9-extension-points-for-v2)

---

## 1. Architecture Overview

mcp-vet v1 is a single-process CLI tool written in TypeScript. It follows a pipeline architecture where an MCP server definition flows through a series of analyzers, each producing findings that feed into a scoring engine.

**v2 update:** The architecture now includes two analysis tracks: metadata analysis (tool definitions, descriptions, parameters) and source code analysis (server implementation). Both tracks feed into the same scoring engine.

### Core Modules

| Module | Responsibility | Input | Output |
|--------|---------------|-------|--------|
| CLI Entry | Argument parsing, orchestration | User args | Exit code + report |
| Server Loader | Reads MCP config, resolves tool defs + source | Path or package name | ServerDefinition object |
| Metadata Analyzer | Runs detection rules against tool defs | ServerDefinition | Finding[] |
| Source Analyzer | AST-based taint analysis for classical vulns (ts-morph for TS/JS, pattern-aware parsing for Python) | Server source files | Finding[] |
| Cross-Server Analyzer | Analyzes multi-server configs for toxic flows | ServerDefinition[] | Finding[] |
| Supply Chain Checker | Checks packages against CVE databases | Package name + version | Finding[] |
| Scoring Engine | Calculates trust score from all findings | Finding[] | TrustScore |
| Report Generator | Produces CLI output and HTML report | TrustScore + Finding[] | stdout + .html file |

### Key Data Types

```typescript
interface ServerDefinition {
  name: string;
  version: string;
  tools: ToolDefinition[];
  config?: ServerConfig;
  sourcePath?: string;        // path to server source for code analysis
  packageInfo?: PackageInfo;  // npm/pypi metadata
  capabilities?: {            // declared MCP capabilities
    sampling?: boolean;       // NEW: does server use sampling?
    resources?: boolean;
    prompts?: boolean;
  };
}

interface Finding {
  id: string;                    // e.g. PI-001, SC-002, TS-001
  vector: AttackVector;
  severity: Severity;
  title: string;
  description: string;
  toolName: string;
  evidence: string;
  cveRef?: string;
  recommendation: string;
  confidence: number;            // 0.0 - 1.0
}

enum AttackVector {
  PROMPT_INJECTION,
  TOOL_POISONING,
  DATA_EXFILTRATION,
  PRIVILEGE_ESCALATION,
  DENIAL_OF_WALLET,
  CROSS_SERVER_SHADOWING,   // NEW
  IMPLEMENTATION_VULN,      // NEW
  SUPPLY_CHAIN,             // NEW
}
```

---

## 2. Data Flow

The pipeline processes an MCP server through two parallel analysis tracks, followed by cross-server analysis if multiple servers are configured.

### Stage 1: Server Loading

The loader accepts three input types and normalizes them into a ServerDefinition:

- **Local path:** `./my-mcp-server` — reads package.json, resolves tool definitions and source files
- **npm package:** `@modelcontextprotocol/server-github` — fetches from registry, extracts tool defs and package metadata
- **MCP config file:** `mcp.json` — parses the config, loads each referenced server, enables cross-server analysis

### Stage 2: Parallel Analysis

Two analysis tracks run concurrently:

> **Track A: Metadata Analysis** — tool definitions, descriptions, parameters, capabilities

Runs analyzers 3.1 through 3.5 (prompt injection, tool poisoning, data exfiltration, privilege escalation, denial of wallet). Pure regex/heuristic against tool metadata.

> **Track B: Source Code Analysis** — server implementation files

Runs analyzer 3.7 (implementation vulnerabilities). Uses AST-based taint analysis via `ts-morph` for TypeScript/JavaScript servers and pattern-aware parsing for Python servers. Traces arguments to dangerous sink functions backward through the AST to distinguish safe static input from dangerous dynamic input. Only runs if source is available.

### Stage 3: Cross-Server Analysis

If the input is an mcp.json with multiple servers, runs analyzer 3.6 (cross-server shadowing). Builds a tool capability graph and checks for toxic flows between servers.

### Stage 4: Supply Chain Check

Runs analyzer 3.8 (supply chain and credential hygiene). Checks package metadata against known CVE databases and evaluates credential management patterns.

### Stage 5: Scoring & Reporting

All findings from all tracks are merged, deduplicated, and fed into the scoring engine.

| Priority | Analyzer | Weight | Track |
|----------|----------|--------|-------|
| 1 | PromptInjectionAnalyzer | 25% | Metadata |
| 2 | CrossServerShadowingAnalyzer | 18% | Cross-Server |
| 3 | ImplementationVulnAnalyzer | 17% | Source Code |
| 4 | ToolPoisoningAnalyzer | 15% | Metadata |
| 5 | DataExfiltrationAnalyzer | 10% | Metadata |
| 6 | PrivilegeEscalationAnalyzer | 5% | Metadata |
| 7 | SupplyChainAnalyzer | 5% | Package |
| 8 | DenialOfWalletAnalyzer | 5% | Metadata |

---

## 3. Detection Engine: Rule Specifications

**30 detection rules** across 8 attack vectors. All v1 rules are pure regex/heuristic — no external API calls. Rules marked **NEW** were added based on the March 2026 threat landscape review and competitor implementation analysis.

---

### 3.1 Prompt Injection Detection

**Weight: 25% of trust score | 8 rules**

OWASP #1 vulnerability for LLM applications. Anthropic system card: 17.8% single-attempt success rate.

#### PI-001: Instruction Override Keywords

Detects keywords and phrases in tool descriptions that attempt to override the model's system prompt.

**Severity:** CRITICAL | **Confidence:** 0.9

```regex
/ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i
/forget\s+(all\s+)?(previous|prior|above|earlier)/i
/disregard\s+(all\s+)?(previous|prior|above|earlier)/i
/override\s+(all\s+)?(previous|prior|system)/i
/you\s+are\s+now\s+/i
/new\s+instructions?\s*:/i
/system\s*:\s*/i
/<\s*(?:IMPORTANT|SYSTEM|instructions?|override|context)\s*>/i
```

**CVE:** CVE-2025-68143 (Anthropic Git MCP server)

#### PI-002: Secrecy Directives

Detects instructions telling the model to hide actions from users. Near-zero false positive rate — no legitimate tool requests secrecy.

**Severity:** CRITICAL | **Confidence:** 0.95 | **Auto-fail trigger**

```regex
/do\s+not\s+(mention|tell|reveal|disclose|show|display|inform)/i
/don'?t\s+(mention|tell|reveal|disclose|show|display|inform)/i
/without\s+(notifying|telling|informing|alerting)/i
/keep\s+(this|it)\s+(secret|hidden|private|between\s+us)/i
/be\s+(gentle|subtle|quiet|discreet)\s+and\s+not\s+scary/i
/never\s+(reveal|mention|disclose|tell)/i
```

#### PI-003: Sensitive File Path References

Tool descriptions referencing SSH keys, AWS credentials, .env files, or other sensitive paths.

**Severity:** CRITICAL | **Confidence:** 0.85

```regex
/~\/.ssh/i, /~\/.aws/i, /~\/.gnupg/i, /\.env(\b|\.)/i
/mcp\.json/i, /credentials?\.json/i, /\.cursor\/mcp\.json/i
/id_rsa/i, /private[_-]?key/i, /\.kube\/config/i
/process\.env/i, /os\.environ/i
/\$\{?[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\}?/i
```

#### PI-004: Invisible Unicode Characters

Zero-width characters, RTL markers, homoglyphs, and Unicode tags used for steganography.

**Severity:** CRITICAL | **Confidence:** 0.98 | **Auto-fail trigger (if >50 chars hidden)**

```regex
/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/     // zero-width
/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/          // directional
/[\uE0001-\uE007F]/                                   // tag characters
```

#### PI-005: Description Length Anomaly

Unusually long descriptions (>500 chars) are a signal for hidden instructions.

**Severity:** MEDIUM–CRITICAL | **Confidence:** 0.5 | Escalates by length

#### PI-006: Base64 Encoded Payloads — NEW

> Identified from MCPhound's POISON-BASE64 pattern.

Detects long base64-encoded strings in tool descriptions. Attackers encode malicious instructions as base64 to evade keyword-based detection.

**Severity:** HIGH | **Confidence:** 0.75

```regex
// Base64 strings >50 chars in descriptions
/[A-Za-z0-9+\/]{50,}={0,2}/

// Also check for decode instructions nearby
/(?:decode|atob|base64|b64decode)/i
```

#### PI-007: Identity / System Prompt Injection — NEW

> Identified from MCPhound's POISON-SYSTEM-PROMPT pattern.

Detects attempts to redefine the model's identity or system prompt from within a tool description.

**Severity:** CRITICAL | **Confidence:** 0.85

```regex
/you\s+are\s+(a|an|now|the)\s+/i
/your\s+(role|purpose|mission|goal)\s+(is|:)/i
/act\s+as\s+(a|an|if)\s+/i
/from\s+now\s+on\s*,?\s+you/i
/pretend\s+(to\s+be|you\s+are)/i
/assume\s+the\s+(role|identity)/i
```

#### PI-008: Tool Redirect Instructions — NEW

> Identified from MCPhound's POISON-TOOL-REDIRECT pattern.

Detects a tool description instructing the model to use a different tool instead, routing the model away from legitimate tools toward attacker-controlled ones.

**Severity:** HIGH | **Confidence:** 0.8

```regex
/instead\s+(of\s+this|use|call|invoke)/i
/always\s+(use|prefer|call)\s+/i
/do\s+not\s+(use|call|invoke)\s+this\s+tool/i
/use\s+.*\s+instead\s+of\s+this/i
/this\s+tool\s+is\s+(deprecated|obsolete|replaced)/i
```

**Real-world basis:** MCP Preference Manipulation Attacks (MPMA) alter how agents rank and select tools.

---

### 3.2 Tool Poisoning & Rug Pull Detection

**Weight: 15% of trust score | 4 rules**

#### TP-001: Lookalike Tool Name Detection

Levenshtein distance and homoglyph comparison against registry of ~50 trusted MCP tool names.

**Severity:** HIGH | **Confidence:** 0.7 | **CVE:** Fake Postmark MCP server (2025)

#### TP-002: Name-Description Semantic Mismatch

Keyword-based category classification. A math tool mentioning HTTP/email/payment terms is flagged.

**Severity:** HIGH | **Confidence:** 0.65

#### TP-003: Description Version Diffing (Rug Pull Defense)

Stores snapshots in `~/.mcp-vet/snapshots/`. On subsequent scans, diffs against snapshot. Changes introducing PI-001/PI-002 patterns auto-escalate to CRITICAL.

**Severity:** INFO–CRITICAL (depends on delta) | **Confidence:** 0.9

#### TP-004: Hidden Content After Visible Text

Detects trailing whitespace/non-printing chars (>20 chars) or large mid-string gaps used for steganographic payloads.

**Severity:** CRITICAL | **Confidence:** 0.9

---

### 3.3 Data Exfiltration Detection

**Weight: 10% of trust score | 3 rules**

#### DE-001: External URL References in Descriptions

Flags URLs pointing to domains outside the tool's expected scope.

**Severity:** HIGH | **Confidence:** 0.75

#### DE-002: Credential-Harvesting Parameter Patterns

Parameters named api_key, secret, token, password in tools whose purpose doesn't justify them.

**Severity:** HIGH | **Confidence:** 0.7

#### DE-003: Broad File Path Parameters

Non-file tools with parameters accepting arbitrary file paths.

**Severity:** MEDIUM | **Confidence:** 0.6

---

### 3.4 Privilege Escalation Detection

**Weight: 5% of trust score | 3 rules**

#### PE-001: Over-Broad OAuth Scopes

OAuth scopes exceeding the tool's stated functionality.

**Severity:** HIGH

#### PE-002: Dangerous Tool Combinations

Known toxic pairs when scanning multi-server configs: Git + Filesystem = RCE; Read tool + HTTP tool = exfiltration.

**Severity:** CRITICAL | **CVE:** Anthropic Git + Filesystem chaining (patched Dec 2025)

#### PE-003: Network Binding Check

Flags servers binding to 0.0.0.0 (accessible to entire local network).

**Severity:** CRITICAL | **Confidence:** 0.95 | **CVE:** NeighborJack (June 2025), CVE-2026-27825 (mcp-atlassian)

---

### 3.5 Denial of Wallet Detection

**Weight: 5% of trust score | 2 rules**

#### DW-001: Recursive Call Instructions

Tool descriptions instructing loops, self-referential calls, or chaining.

**Severity:** HIGH

#### DW-002: Missing Rate Limit Configuration

No rate limiting, timeout, or token budget settings found in server config.

**Severity:** MEDIUM (escalates to HIGH with DW-001)

---

### 3.6 Cross-Server Shadowing Detection — NEW

> This was the most critical missing vector identified in the gap analysis.

**Weight: 18% of trust score | 3 rules**

A malicious server injects tool descriptions that modify the agent's behavior with respect to tools from other, trusted servers. Invariant Labs demonstrated an attack where a malicious MCP server's description caused the Cursor agent to silently redirect all emails to the attacker.

#### TS-001: Cross-Tool Behavioral Instructions

Detects tool descriptions that reference or instruct behavior for tools they don't own.

**Severity:** CRITICAL | **Confidence:** 0.85

```typescript
// Step 1: Build tool ownership map from all servers in config
// { 'send_email': 'email-server', 'list_repos': 'github-server', ... }

// Step 2: For each tool, scan description for references to other tools
const foreignToolRef = allToolNames.filter(
  name => name !== currentTool && description.includes(name)
);

// Step 3: Flag if description contains behavioral instructions targeting foreign tools
/when\s+(calling|using|invoking)\s+/i  // + foreign tool name
/instead\s+of\s+/i                     // override pattern
/redirect.*to/i                         // redirect pattern
/also\s+(send|forward|copy)/i           // piggyback pattern
/before\s+(calling|using)/i             // pre-hook pattern
```

#### TS-002: Sampling Capability Detection

Flags servers that declare MCP sampling capabilities. Sampling allows a server to request LLM completions, enabling conversation hijacking, resource theft, and covert tool invocation.

**Severity:** HIGH | **Confidence:** 0.8

**Research basis:** Palo Alto Unit 42 (Dec 2025) — three PoC attacks via sampling.

#### TS-003: Toxic Flow Graph Analysis

Builds a directed graph of capabilities across all configured servers. Identifies multi-hop attack paths.

**Severity:** CRITICAL | **Confidence:** 0.75

```typescript
const TOXIC_FLOWS = [
  { path: ['READ_SECRETS', 'HTTP_OUT'], risk: 'Credential exfiltration' },
  { path: ['READ_FILES', 'HTTP_OUT'], risk: 'File exfiltration' },
  { path: ['READ_FILES', 'SEND_EMAIL'], risk: 'Data leak via email' },
  { path: ['DB_ACCESS', 'HTTP_OUT'], risk: 'Database exfiltration' },
  { path: ['READ_FILES', 'EXEC_CODE'], risk: 'Read + execute chain' },
  { path: ['WRITE_FILES', 'EXEC_CODE'], risk: 'Write + execute = RCE' },
];
```

---

### 3.7 Implementation Vulnerability Detection — NEW

> Addresses the biggest gap: classical web vulnerabilities in server source code.

**Weight: 17% of trust score | 4 rules**

Endor Labs: 82% of MCP implementations have path traversal-prone code, 67% have code injection-prone APIs, 34% have command injection-prone APIs.

**Requirement:** These rules only run when server source code is available. When auditing without source, these are skipped with a note in the report.

**Approach: AST-based taint analysis** — v1 uses `ts-morph` (wraps the TypeScript compiler API, 4.5k+ stars) for TypeScript/JavaScript servers. For Python servers, a pattern-aware parser inspects dangerous function calls and distinguishes string literals from variable references (lighter than full taint analysis, but significantly more accurate than raw regex). This replaces the regex-based approach from the earlier design, eliminating false positives on safe static code and catching obfuscated dynamic input patterns.

**Dependency:** `ts-morph` is the one new dependency added to the project for source analysis.

#### SC-001: Command Injection — AST Taint Analysis

Server source code passing unsanitized input to shell execution functions.

**Severity:** CRITICAL | **Confidence:** 0.85

**Sink functions (TypeScript/JavaScript):** `child_process.exec`, `child_process.execSync`, `child_process.spawn` (with `shell: true`), `eval`
**Sink functions (Python):** `os.system`, `subprocess.call/run/Popen/check_output` (with `shell=True`), `eval`, `exec`

**Detection method:** Parse the AST. Find all call expressions to sink functions. For each call, trace the first argument backward through the AST:

- **String literal or constant** → safe, no finding
- **Template literal with `${}` interpolation** → dangerous, CRITICAL finding
- **String concatenation (`+`) with any non-constant value** → dangerous, CRITICAL finding
- **Variable reference** → trace backward: if it resolves to a function parameter, `req.body`, `req.params`, tool input schema field, or any external source → dangerous, CRITICAL finding

```typescript
// ts-morph approach
const sourceFile = project.addSourceFileAtPath(filePath);
const callExpressions = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

for (const call of callExpressions) {
  const funcName = call.getExpression().getText();
  if (!EXEC_SINK_FUNCTIONS.includes(funcName)) continue;

  const firstArg = call.getArguments()[0];
  if (!firstArg) continue;

  if (firstArg.getKind() === SyntaxKind.StringLiteral) {
    // Static string — safe, skip
    continue;
  }

  if (firstArg.getKind() === SyntaxKind.TemplateExpression) {
    // Template literal with interpolation — dangerous
    findings.push({ id: 'SC-001', severity: 'CRITICAL', ... });
    continue;
  }

  if (firstArg.getKind() === SyntaxKind.BinaryExpression) {
    // String concatenation — dangerous
    findings.push({ id: 'SC-001', severity: 'CRITICAL', ... });
    continue;
  }

  // Variable reference — trace it back to source
  if (isTracedToExternalInput(firstArg, sourceFile)) {
    findings.push({ id: 'SC-001', severity: 'CRITICAL', ... });
  }
}
```

**CVE:** CVE-2025-6514 (mcp-remote, CVSS 9.6), CVE-2025-5277 (aws-mcp-server)

#### SC-002: SSRF — URL Argument Taint Analysis

URL fetching without domain validation or private IP blocking. ~36.7% of MCP servers have latent SSRF exposure.

**Severity:** HIGH | **Confidence:** 0.7

**Sink functions:** `fetch`, `axios.get`, `axios.post`, `axios.request`, `http.request`, `https.request`, `requests.get`, `requests.post`, `urllib.request.urlopen`

**Detection method:** Find all call expressions to sink functions. Trace the URL argument:

- **String literal** → safe, no finding
- **Variable** → check whether any URL validation function is called on the variable before it reaches the fetch call. Validation functions: `isPrivateIP`, `validateUrl`, `URL` constructor with domain check, allowlist comparison, `.includes()` against a domain list. **No validation found** → HIGH finding

**CVE:** CVE-2026-27826 (mcp-atlassian), CVE-2025-65513 (fetch MCP server, CVSS 9.3)

#### SC-003: Path Traversal — File Op Path Validation Analysis

File operations with user-controlled paths and insufficient validation.

**Severity:** HIGH | **Confidence:** 0.75

**Sink functions:** `fs.readFile`, `fs.readFileSync`, `fs.writeFile`, `fs.writeFileSync`, `fs.readdir`, `fs.unlink`, `fs.access`, `open()` (Python)

**Detection method:** Find all call expressions to sink functions. Trace the path argument:

- **String literal** → safe, no finding
- **Variable** → check whether proper containment validation exists before the file operation:
  - `path.resolve()` + `startsWith()` together → safe (proper containment)
  - `fs.realpath()` / `fs.realpathSync()` before access → safe
  - **`startsWith()` without `path.resolve()`** → HIGH finding (prefix bypass vulnerability, per CVE-2025-53110 pattern: `/private/tmp/allow_dir_sensitive_credentials` passes a `startsWith('/private/tmp/allow_dir')` check)
  - **No validation at all** → HIGH finding

**CVE:** CVE-2025-53110 (EscapeRoute sandbox bypass), CVE-2025-68145 (Git MCP path validation bypass), CVE-2026-27825 (mcp-atlassian)

#### SC-004: SQL Injection — Query Argument Type Analysis

Unsafe construction of SQL/NoSQL queries with user input.

**Severity:** HIGH | **Confidence:** 0.8

**Sink functions:** `.query()`, `.execute()`, `db.run()`, `db.all()`, `cursor.execute()` (Python)

**Detection method:** Find all call expressions to sink functions. Check the first argument:

- **Tagged template literal** (e.g., `` sql`SELECT * FROM users WHERE id = ${id}` ``) → safe (parameterized by the tag function)
- **Contains placeholder tokens** (`$1`, `?`, `%s`, `:name`) with a second argument (params array) → safe (parameterized query)
- **Regular template literal with `${}` interpolation** (no tag) → HIGH finding
- **String concatenation with any non-constant value** → HIGH finding

**Real-world basis:** Supabase Cursor agent breach (mid-2025)

---

### 3.8 Supply Chain & Credential Hygiene — NEW

> Addresses supply chain attacks and insecure credential management.

**Weight: 5% of trust score | 3 rules**

Astrix research: 53% of MCP servers rely on static API keys, only 8.5% use OAuth, 79% pass keys via environment variables.

#### SU-001: Known CVE Check

Cross-references the server's package name and version against OSV.dev (free, no API key).

**Severity:** Matches CVE severity | **Confidence:** 1.0

#### SU-002: Credential Management Assessment

Flags static API keys in config, missing OAuth, overly broad PATs, plaintext credential storage.

**Severity:** MEDIUM–HIGH | **Confidence:** 0.7

#### SU-003: Untrusted Content Processing

Flags tools that process external user-generated content (GitHub issues, emails, web pages) without mentioning sanitization.

**Severity:** MEDIUM | **Confidence:** 0.6

---

## 4. Trust Scoring Model

### Scoring Formula

```
deduction = severity_weight × confidence × vector_weight
```

**Severity weights:**

| Severity | Base Deduction | Rationale |
|----------|---------------|-----------|
| CRITICAL | 25 points | Actively exploitable, documented in real CVEs |
| HIGH | 15 points | Likely exploitable, requires minimal effort |
| MEDIUM | 8 points | Potentially exploitable, requires specific conditions |
| LOW | 3 points | Theoretical risk, defense-in-depth concern |
| INFO | 0 points | Informational, no deduction |

**Vector weights (revised):**

| Vector | Weight | Change | Rationale |
|--------|--------|--------|-----------|
| Prompt Injection | 25% (1.0) | Was 35% | Still #1 but other vectors share weight |
| Cross-Server Shadowing | 18% (0.85) | NEW | Most dangerous multi-server attack |
| Implementation Vulns | 17% (0.8) | NEW | 82% of servers have path traversal-prone code |
| Tool Poisoning | 15% (0.7) | Was 25% | Partially overlaps with shadowing |
| Data Exfiltration | 10% (0.5) | Was 20% | Often caught by other rules |
| Privilege Escalation | 5% (0.3) | Was 12% | Limited in static analysis |
| Supply Chain | 5% (0.3) | NEW | Binary signal (CVE exists or not) |
| Denial of Wallet | 5% (0.25) | Was 8% | Bounded by API spend limits |

### Grade Thresholds

| Grade | Score | Meaning | CI/CD |
|-------|-------|---------|-------|
| **A** | 90–100 | No significant risks | Pass |
| **B** | 75–89 | Minor risks, generally safe | Pass (warnings) |
| **C** | 50–74 | Moderate risks, review needed | Configurable |
| **D** | 25–49 | Serious risks, use with caution | Fail |
| **F** | 0–24 | Critical risks, do not use | Fail |

### Auto-Fail Conditions (Grade F)

- Any PI-002 (secrecy directive) finding
- Any PI-004 (invisible Unicode) with >50 hidden characters
- Any TS-001 (cross-server shadowing) with behavioral override detected
- Any SC-001 (command injection) with unsanitized user input in exec()
- Any SU-001 finding with CVSS score ≥ 9.0
- 3+ CRITICAL findings from different vectors

---

## 5. Claude CLI Auto-Discovery

> **NEW SECTION** — Built specifically for Claude Code CLI as the primary target.

mcp-vet is built for the Claude ecosystem first. Rather than requiring users to specify config file paths, the CLI auto-discovers MCP server configurations from Claude Code's known config locations.

### Claude Code Config Locations

```
// Global config (user-level, applies to all projects)
~/.claude/claude_desktop_config.json
~/.claude.json

// Project-level config (per-repo)
./.mcp.json                    // project root
./.claude/mcp.json             // project .claude dir
./claude_desktop_config.json   // legacy

// VS Code integration
./.vscode/mcp.json

// Claude Code settings that reference MCP servers
~/.claude/settings.json        // may contain enabledMcpjsonServers
./.claude/settings.local.json  // project-level overrides
```

### Discovery Behavior

- **Default:** When run with no arguments (`npx mcp-vet`), auto-discovers all Claude Code configs starting from global config, then current directory's project config.
- **Project mode:** `--project` scans only the current directory's MCP configuration. Useful in CI/CD.
- **Explicit path:** `npx mcp-vet audit ./mcp.json` uses only that file.
- **Multi-config merge:** If both global and project configs exist, merges them (project overrides global) and runs cross-server analysis across the combined set. This matches how Claude Code actually resolves MCP servers.

### Why Claude CLI First

Claude Code is the highest-risk MCP client because it runs with developer-level system access. Check Point Research discovered CVE-2025-59536 and CVE-2026-21852 specifically in Claude Code's MCP handling — malicious project configurations could achieve RCE and API key exfiltration.

Competitors support multiple clients but spread thin. By focusing on Claude Code CLI specifically, mcp-vet covers the config hierarchy, settings overrides, and project-level patterns that Claude Code uniquely uses.

### Future: Additional Client Support

After Claude Code CLI is solid: Claude Desktop (different config location), then Cursor, Windsurf, Gemini CLI (v2 stretch goal).

---

## 6. Report Generation & Output Formats

### Terminal Output

ANSI-colored output modeled on eslint and npm audit. Color mapping: CRITICAL (red bg), HIGH (orange), MEDIUM (yellow), LOW (blue), INFO (gray).

### HTML Report

Self-contained single file (inline CSS, no JS dependencies):

- Header with server name, version, scan timestamp, mcp-vet version
- Trust score as colored circle with letter grade
- Findings grouped by severity with expandable details
- Vector breakdown chart showing per-category scores
- Toxic flow diagram — visual graph of cross-server attack paths
- Evidence section with exact triggering patterns
- Known CVE cross-references with links
- Recommendations with actionable fix instructions

### SARIF Output — NEW

> Adopted from MCPhound. Standard format for GitHub Code Scanning.

`--sarif` flag outputs findings in SARIF 2.1.0 format. This enables direct integration with GitHub Code Scanning, Azure DevOps, and other SARIF-consuming tools. Findings appear as annotations in pull requests.

---

## 7. CLI Interface Design

```bash
# Auto-discover Claude Code configs and audit everything
npx mcp-vet

# Audit current project's MCP config only
npx mcp-vet --project

# Audit a specific config file
npx mcp-vet audit ./mcp.json

# Audit a published npm package
npx mcp-vet audit @modelcontextprotocol/server-github

# Generate HTML report
npx mcp-vet audit ./mcp.json --report

# CI mode: exit 1 on critical/high, SARIF output
npx mcp-vet audit ./mcp.json --ci --sarif results.sarif

# JSON output
npx mcp-vet audit ./mcp.json --json

# Skip source code / CVE analysis
npx mcp-vet audit ./mcp.json --no-source --no-cve

# Compare against last snapshot (rug-pull detection)
npx mcp-vet diff

# Show toxic flow graph for multi-server config
npx mcp-vet graph

# List all 30 detection rules
npx mcp-vet list-rules
```

### Configuration

```yaml
# .mcp-vet.yml
failOn: [critical, high]
ignore:
  - PI-005                     # Suppress description length warnings
  - DW-002                     # Suppress rate limit warnings
trustedDomains:
  - api.mycompany.com
trustedServers:               # Skip shadowing analysis for these
  - @modelcontextprotocol/server-github
snapshotDir: .mcp-vet/
sourceAnalysis: true
cveCheck: true
```

---

## 8. Competitive Analysis

> **UPDATED** — Now includes findings from reviewing competitors' GitHub repos and source code.

### Active Competitors

| Tool | Owner | Approach | Strengths | Weaknesses |
|------|-------|----------|-----------|------------|
| Snyk agent-scan v0.4.5 | Snyk (acquired Invariant) | Python CLI, connects to live servers, uses Snyk API. 1.8k stars, 365 commits, 12 contributors. | 15+ risk types, auto-discovers 6 clients, proxy mode, toxic flow analysis, background scanning | Requires Snyk API key + signup, sends data to Snyk servers, Python/uv dependency, closed to contributions, no source code analysis, no HTML report or trust grades |
| MCPhound v3 | Independent (tayler-id) | Node CLI + FastAPI backend + PostgreSQL. 1 star, 29 commits. | Cross-server graph with friction-based scoring, 10 regex poisoning patterns, SARIF output, A-F grading, web UI | Requires API backend (not offline), no source code analysis, tiny community (1 star) |
| Ant Group MCPScan | Ant Group | Python, 3-stage: Semgrep + LLM + cross-file flow. | Only tool doing code-level taint analysis, Semgrep rules for CWEs | Requires LLM API for stages 2-3, Python-only, research-oriented, no CI/CD |

### Implementation Patterns Adopted from Competitors

- **From Snyk agent-scan:** Auto-discovery of agent configs — adapted for Claude CLI specifically rather than spreading across 6 clients
- **From MCPhound:** 3 new detection patterns (PI-006 base64 payloads, PI-007 system prompt injection, PI-008 tool redirect). Also: SARIF output, OSV.dev for CVE lookups, friction-based edge weights for toxic flow graph
- **From Ant Group MCPScan:** Taint analysis concept for SC-001 through SC-004, implemented as AST-based analysis via `ts-morph` (no Semgrep dependency, no external API calls)

### mcp-vet Differentiation

- **Zero dependencies, zero API keys:** Pure regex/heuristic runs entirely offline. Snyk requires API key and sends data to their servers.
- **Combined metadata + AST source analysis:** Neither Snyk nor MCPhound scan server source code. mcp-vet uses `ts-morph` for real taint analysis, not just regex.
- **TypeScript-native:** Matches the MCP ecosystem. Competitors are Python.
- **Claude CLI-first:** Deep integration with Claude Code's config hierarchy.
- **CI/CD-first design:** GitHub Actions, exit codes, SARIF output, `.mcp-vet.yml` config.
- **Trust scoring with grades:** A–F grades with HTML reports for CISOs.
- **Vendor-neutral, fully open source:** No freemium gate.

### Positioning Statement

> *"The offline, zero-dependency MCP security auditor built for Claude Code. Combines tool definition analysis with source code scanning in a single TypeScript CLI. Auto-discovers your Claude configs. No API keys. No data leaves your machine. Runs in CI/CD with SARIF output."*

---

## 9. Extension Points for v2

### Claude-Powered Semantic Analysis

Replace TP-002 and TS-001 with Claude API calls for semantic evaluation. Optional `--claude` flag.

### Dynamic Testing Engine

Connect to a live MCP server and probe with adversarial inputs. Catches runtime behavior that static analysis cannot.

### Community Rule Contributions

Detection rules loadable from external YAML files. Enables contributions without modifying core code.

### Public Audit Registry

Public API showing audit results for community MCP servers. The network effect driver.

### MCP Proxy Mode — NEW

Real-time monitoring mode. Sits between MCP client and server, monitoring live traffic for behavioral anomalies and sampling abuse.

---

## Appendix: Complete Rule Index

| ID | Name | Vector | Severity | New? |
|----|------|--------|----------|------|
| PI-001 | Instruction Override Keywords | Prompt Injection | CRITICAL | |
| PI-002 | Secrecy Directives | Prompt Injection | CRITICAL | |
| PI-003 | Sensitive File Path References | Prompt Injection | CRITICAL | |
| PI-004 | Invisible Unicode Characters | Prompt Injection | CRITICAL | |
| PI-005 | Description Length Anomaly | Prompt Injection | MED–CRIT | |
| **PI-006** | **Base64 Encoded Payloads** | **Prompt Injection** | **HIGH** | **✓** |
| **PI-007** | **Identity / System Prompt Injection** | **Prompt Injection** | **CRITICAL** | **✓** |
| **PI-008** | **Tool Redirect Instructions** | **Prompt Injection** | **HIGH** | **✓** |
| TP-001 | Lookalike Tool Name Detection | Tool Poisoning | HIGH | |
| TP-002 | Name-Description Mismatch | Tool Poisoning | HIGH | |
| TP-003 | Description Version Diffing | Tool Poisoning | INFO–CRIT | |
| TP-004 | Hidden Content After Visible Text | Tool Poisoning | CRITICAL | |
| DE-001 | External URL References | Data Exfiltration | HIGH | |
| DE-002 | Credential-Harvesting Params | Data Exfiltration | HIGH | |
| DE-003 | Broad File Path Parameters | Data Exfiltration | MEDIUM | |
| PE-001 | Over-Broad OAuth Scopes | Privilege Escalation | HIGH | |
| PE-002 | Dangerous Tool Combinations | Privilege Escalation | CRITICAL | |
| PE-003 | Network Binding Check | Privilege Escalation | CRITICAL | |
| DW-001 | Recursive Call Instructions | Denial of Wallet | HIGH | |
| DW-002 | Missing Rate Limits | Denial of Wallet | MEDIUM | |
| **TS-001** | **Cross-Tool Behavioral Instructions** | **Cross-Server Shadowing** | **CRITICAL** | **✓** |
| **TS-002** | **Sampling Capability Detection** | **Cross-Server Shadowing** | **HIGH** | **✓** |
| **TS-003** | **Toxic Flow Graph Analysis** | **Cross-Server Shadowing** | **CRITICAL** | **✓** |
| **SC-001** | **Command Injection Patterns** | **Implementation Vuln** | **CRITICAL** | **✓** |
| **SC-002** | **SSRF Patterns** | **Implementation Vuln** | **HIGH** | **✓** |
| **SC-003** | **Path Traversal Patterns** | **Implementation Vuln** | **HIGH** | **✓** |
| **SC-004** | **Unsafe Database Queries** | **Implementation Vuln** | **HIGH** | **✓** |
| **SU-001** | **Known CVE Check** | **Supply Chain** | **Matches CVE** | **✓** |
| **SU-002** | **Credential Management** | **Supply Chain** | **MED–HIGH** | **✓** |
| **SU-003** | **Untrusted Content Processing** | **Supply Chain** | **MEDIUM** | **✓** |

---

*End of Technical Design Document v3.0 — mcp-vet — March 2026*
