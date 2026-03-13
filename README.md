# mcp-vet

Open-source security auditor for MCP (Model Context Protocol) servers. Scans server definitions and source code for vulnerabilities before you connect them to Claude or other AI agents.

## Quick Start

```bash
# Auto-discover and audit all MCP configs on your machine
npx mcp-vet

# Audit a specific config file
npx mcp-vet audit ./mcp.json

# Audit an npm package directly
npx mcp-vet audit @modelcontextprotocol/server-filesystem
```

## What It Detects

**30 detection rules** across 8 attack vectors:

| Vector | Rules | Examples |
|--------|-------|---------|
| Prompt Injection | PI-001–008 | Override keywords, secrecy directives, Unicode obfuscation, identity injection |
| Tool Poisoning | TP-001–004 | Lookalike names, name-description mismatch, hidden trailing text |
| Data Exfiltration | DE-001–003 | External URLs in descriptions, credential-harvesting parameters |
| Privilege Escalation | PE-001–003 | Over-broad OAuth scopes, dangerous tool combos, network binding |
| Denial of Wallet | DW-001–002 | Recursive call instructions, missing rate limits |
| Cross-Server | TS-001–003 | Cross-tool instructions, sampling, toxic flow graphs |
| Implementation Vulns | SC-001–004 | Command injection, SSRF, path traversal, SQL injection |
| Supply Chain | SU-001–003 | Known CVEs, credential management, untrusted content |

## Features

- **Zero external API calls** — everything runs locally, nothing leaves your machine
- **Live server connections** — connects via stdio, pulls real tool definitions
- **AST-based source analysis** — uses `ts-morph` for TypeScript/JavaScript and `tree-sitter` (WASM) for Python taint tracing
- **Multiple output formats** — terminal, JSON, HTML reports, SARIF 2.1.0
- **CI/CD ready** — `--ci` flag exits 1 on critical/high findings
- **Auto-discovery** — finds Claude Desktop, Claude CLI, VS Code MCP configs automatically
- **Trust scoring** — A–F grades with auto-fail conditions for critical vulnerabilities

## Commands

```bash
npx mcp-vet                          # Auto-discover and scan all MCP configs
npx mcp-vet --project                # Scan only project-level configs
npx mcp-vet audit <target>           # Audit a config file or npm package
npx mcp-vet audit <target> --json    # JSON output
npx mcp-vet audit <target> --report  # Generate HTML report
npx mcp-vet audit <target> --sarif out.sarif  # SARIF output
npx mcp-vet audit <target> --ci      # CI mode (exit 1 on critical/high)
npx mcp-vet audit <target> --no-source  # Skip source code analysis
npx mcp-vet diff <path>              # Rug-pull detection vs snapshot
npx mcp-vet graph <path>             # Show toxic flow graph
npx mcp-vet list-rules               # List all 30 detection rules
```

## Example Output

```
╔═════════════════════════════════════════════════════════╗
║                                                         ║
║     Trust Score: 24/100       Grade: F                  ║
║                                                         ║
║     ⚠ AUTO-FAIL: Command injection (SC-001)             ║
║                                                         ║
╚═════════════════════════════════════════════════════════╝

  Findings (4)
  ─────────────────────────────────────────────────────────

  CRITICAL  SC-001  Command Injection
  ├─ Tool: index.js
  ├─ Unsanitized input passed to exec() (22 instances)
  ├─ Evidence: exec(command) at line 19494
  └─ Fix: Use parameterized execution (e.g., execFile with array args)
```

## How Scoring Works

- **100 points** base, deductions per finding severity
- CRITICAL: -25, HIGH: -15, MEDIUM: -8, LOW: -3, INFO: 0
- **Auto-fail** (forced Grade F): secrecy directives, command injection with unsanitized input, instruction override with secrecy
- Grade scale: A (90–100), B (70–89), C (50–69), D (30–49), F (0–29)

## Requirements

- Node.js 20+

## License

MIT
