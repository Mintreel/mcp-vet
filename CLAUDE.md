# mcp-vet

Open-source MCP security auditor CLI. Scans MCP server definitions and source code for vulnerabilities before connecting them to Claude or other AI agents.

## Project Overview

- **Language:** TypeScript
- **Runtime:** Node.js 20+
- **Package manager:** npm
- **Test framework:** vitest
- **CLI framework:** TBD (commander or yargs)
- **Build:** tsup or tsc
- **Linting:** eslint + prettier

## Architecture

Single-process pipeline CLI:

```
Server Loader → Metadata Analyzer (parallel) → Cross-Server Analyzer → Supply Chain Checker → Scoring Engine → Report Generator
                Source Analyzer (parallel) ↗
```

### Core Modules

| Module | Path | Purpose |
|--------|------|---------|
| CLI Entry | `src/cli.ts` | Argument parsing, orchestration |
| Server Loader | `src/loader/` | Reads MCP configs, resolves tool defs + source |
| Metadata Analyzer | `src/analyzers/metadata/` | Runs PI/TP/DE/PE/DW rules against tool defs |
| Source Analyzer | `src/analyzers/source/` | Scans server source for SC-001–004 |
| Cross-Server Analyzer | `src/analyzers/cross-server/` | TS-001–003 toxic flow analysis |
| Supply Chain Checker | `src/analyzers/supply-chain/` | SU-001–003 CVE + credential checks |
| Scoring Engine | `src/scoring/` | Trust score calculation, A–F grading |
| Report Generator | `src/reporters/` | Terminal, HTML, JSON, SARIF output |

### Key Types

- `ServerDefinition` — normalized MCP server with tools, config, source path
- `Finding` — individual security issue with id, severity, confidence, evidence
- `TrustScore` — numeric score (0–100) + letter grade (A–F)
- `AttackVector` — enum of 8 attack categories

## Detection Rules (30 total)

- **PI-001–008:** Prompt injection (override keywords, secrecy, sensitive paths, Unicode, length, base64, identity injection, tool redirect)
- **TP-001–004:** Tool poisoning (lookalike names, name-desc mismatch, rug-pull diffing, hidden trailing text)
- **DE-001–003:** Data exfiltration (external URLs, credential params, broad file paths)
- **PE-001–003:** Privilege escalation (OAuth scopes, dangerous combos, network binding)
- **DW-001–002:** Denial of wallet (recursive calls, missing rate limits)
- **TS-001–003:** Cross-server shadowing (cross-tool instructions, sampling, toxic flows)
- **SC-001–004:** Implementation vulns (command injection, SSRF, path traversal, SQL injection)
- **SU-001–003:** Supply chain (known CVEs, credential management, untrusted content)

## Commands

```bash
npm run build          # Build TypeScript
npm test               # Run unit tests (vitest)
npm run test:coverage  # Run tests with coverage
npm run test:e2e       # Integration tests
npm run lint           # ESLint + Prettier check
```

## CLI Usage

```bash
npx mcp-vet                                    # Auto-discover Claude configs, audit all
npx mcp-vet --project                          # Audit current project's MCP config only
npx mcp-vet audit ./mcp.json                   # Audit specific config
npx mcp-vet audit ./mcp.json --report          # Generate HTML report
npx mcp-vet audit ./mcp.json --ci --sarif out  # CI mode with SARIF
npx mcp-vet audit ./mcp.json --json            # JSON output
npx mcp-vet diff                               # Rug-pull detection vs snapshot
npx mcp-vet graph                              # Show toxic flow graph
npx mcp-vet list-rules                         # List all 30 detection rules
```

## Code Conventions

- Metadata/cross-server/supply-chain rules (26 rules) are pure regex/heuristic — no external API calls
- Source code rules (SC-001–004) use AST-based taint analysis via `ts-morph` for TS/JS, pattern-aware parsing for Python
- Each analyzer returns `Finding[]`
- Findings include: id, vector, severity, title, description, toolName, evidence, recommendation, confidence (0–1)
- Auto-fail conditions force Grade F regardless of numeric score
- Test every rule with at least 3 cases: positive, negative, edge
- Fixtures live in `test-fixtures/malicious/`, `test-fixtures/clean/`, `test-fixtures/edge-cases/`

## Design Principles

- Zero external API dependencies for core scanning (no API keys, nothing leaves the machine). One library dependency: `ts-morph` for AST-based source analysis
- Claude Code CLI-first: auto-discover configs from `~/.claude/`, `.mcp.json`, `.vscode/mcp.json`
- CI/CD-first: exit codes, SARIF output, `.mcp-vet.yml` config file
- TypeScript-native to match the MCP ecosystem

## Documentation

- `Docs/mcp-shield-strategy.md` — Strategy, market research, roadmap
- `Docs/mcp-shield-user-journeys.md` — Persona-based user journey maps
- `Docs/mcp-vet-technical-design (1).md` — Full technical design (30 rules, scoring, architecture)
- `Docs/mcp-vet-test-plan.md` — Comprehensive test plan (90+ test cases)
