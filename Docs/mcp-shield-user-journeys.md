# mcp-shield: User Journey Maps

> How each persona discovers, uses, and gets value from mcp-shield.

---

## Persona 1: Solo Developer Using Claude Code Daily

**Who they are:** Individual developer using Claude Code as their primary coding tool. Has 2-5 MCP servers installed (GitHub, filesystem, maybe a database). Doesn't think about security much until something goes wrong.

**Trigger:** Sees a Hacker News post about MCP vulnerabilities, or notices an mcp-shield badge on a server's README.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SOLO DEVELOPER JOURNEY                          │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────┐     ┌──────────────┐     ┌────────────────────────┐
  │ Sees HN  │────▶│ Runs one cmd │────▶│ Auto-discovers configs  │
  │ post or  │     │              │     │                        │
  │ README   │     │ npx          │     │ ~/.claude/             │
  │ badge    │     │ mcp-shield   │     │ .mcp.json              │
  └──────────┘     └──────────────┘     │ .vscode/mcp.json       │
                                        └───────────┬────────────┘
                                                    │
                                                    ▼
                                        ┌────────────────────────┐
                                        │ Scans all MCP servers  │
                                        │ 30 rules • ~5 seconds  │
                                        │ No API key needed      │
                                        │ Nothing leaves machine │
                                        └───────────┬────────────┘
                                                    │
                                                    ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                    TERMINAL OUTPUT                           │
  │                                                              │
  │  mcp-shield v1.0.0                                          │
  │  Found 3 servers in ~/.claude/claude_desktop_config.json     │
  │                                                              │
  │  TRUST SCORE: B (82/100)                                    │
  │                                                              │
  │  🔴 HIGH  PE-001  Over-broad OAuth scope                    │
  │     Server: github-mcp                                      │
  │     Token grants write access to ALL repositories            │
  │     Fix: Scope PAT to specific repos only                   │
  │                                                              │
  │  🟡 MED   DW-002  No rate limiting configured               │
  │     Server: postgres-mcp                                    │
  │                                                              │
  │  🟡 MED   PI-005  Long description (1,247 chars)            │
  │     Server: filesystem-mcp                                  │
  │                                                              │
  │  3 issues: 1 high, 2 medium                                 │
  └──────────────────────────────────────────────────────────────┘
                                                    │
                                                    ▼
                                        ┌────────────────────────┐
                                        │ Developer fixes config │
                                        │ Narrows OAuth scope    │
                                        │ Re-runs: Grade → A     │
                                        └───────────┬────────────┘
                                                    │
                                                    ▼
                                        ┌────────────────────────┐
                                        │ NEW HABIT FORMED       │
                                        │                        │
                                        │ Before installing any  │
                                        │ new MCP server:        │
                                        │                        │
                                        │ npx mcp-shield audit   │
                                        │ @some/new-mcp-server   │
                                        └────────────────────────┘
```

**Time to value:** Under 30 seconds. One command, zero config, immediate result.

**What makes them come back:** The habit of scanning before installing new servers. Same muscle memory as `npm audit`.

---

## Persona 2: Security Engineer Vetting MCP Servers for Their Team

**Who they are:** AppSec or security engineer at a company using Claude Code across engineering teams. Responsible for approving which MCP servers are allowed. Reports to a CISO.

**Trigger:** Engineering team submits a request to connect Claude to a community MCP server (e.g., Postgres, Slack, or a custom internal tool).

```
┌─────────────────────────────────────────────────────────────────────┐
│                  SECURITY ENGINEER JOURNEY                         │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐
  │ Dev team     │
  │ requests new │
  │ MCP server   │
  └──────┬───────┘
         │
         ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 1: Full audit with HTML report                     │
  │                                                          │
  │ npx mcp-shield audit @community/postgres-mcp --report   │
  └──────────────────────────┬───────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
  ┌────────────────┐ ┌──────────────┐ ┌────────────────┐
  │ TRACK A        │ │ TRACK B      │ │ TRACK C        │
  │ Metadata       │ │ Source Code  │ │ Supply Chain   │
  │ Analysis       │ │ Analysis     │ │ Check          │
  │                │ │              │ │                │
  │ Tool defs,     │ │ Command inj, │ │ Known CVEs,    │
  │ descriptions,  │ │ SSRF, path   │ │ credential     │
  │ parameters     │ │ traversal,   │ │ hygiene,       │
  │ (PI/TP/DE/DW)  │ │ SQL inj      │ │ package age    │
  │                │ │ (SC-001-004) │ │ (SU-001-003)   │
  └───────┬────────┘ └──────┬───────┘ └───────┬────────┘
          └──────────────────┼─────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 2: Cross-server analysis                           │
  │                                                          │
  │ If team already has other MCP servers installed,         │
  │ mcp-shield checks the COMBINATION:                      │
  │                                                          │
  │ postgres-mcp (DB_ACCESS) + filesystem-mcp (READ_FILES)  │
  │ + fetch-mcp (HTTP_OUT) = data exfiltration path          │
  │                                                          │
  │ TS-003 flags: "Database contents can be read and sent    │
  │ to external endpoints via fetch server"                  │
  └──────────────────────────┬───────────────────────────────┘
                             │
                             ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 3: HTML report generated                           │
  │                                                          │
  │ → mcp-shield-report.html                                │
  │                                                          │
  │ Self-contained single file. Contains:                   │
  │  • Trust grade (big colored circle)                     │
  │  • All findings with evidence                           │
  │  • Toxic flow diagram                                   │
  │  • CVE cross-references                                 │
  │  • Actionable recommendations                          │
  │                                                          │
  │ Security engineer attaches to approval ticket.          │
  └──────────────────────────┬───────────────────────────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │                     │
            ┌─────┴─────┐        ┌─────┴─────┐
            │ Grade A/B │        │ Grade C-F │
            │           │        │           │
            │ APPROVED  │        │ BLOCKED   │
            │           │        │           │
            │ Server    │        │ Report    │
            │ added to  │        │ sent back │
            │ allowlist │        │ to dev    │
            │           │        │ team with │
            │ Report    │        │ specific  │
            │ filed in  │        │ fixes     │
            │ security  │        │ required  │
            │ review    │        │           │
            └───────────┘        └───────────┘
```

**Time to value:** 2-3 minutes for full audit + report. Replaces hours of manual code review.

**What makes them come back:** The HTML report. It's the artifact they attach to Jira tickets, present in security reviews, and show to auditors. No other tool produces this.

---

## Persona 3: DevOps Engineer Adding to CI/CD

**Who they are:** Platform/DevOps engineer responsible for the CI/CD pipeline. Wants to prevent insecure MCP configs from being merged into the codebase. Cares about automation, exit codes, and pipeline integration.

**Trigger:** Security team mandates that all MCP configurations must pass a security check before merge.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DEVOPS ENGINEER JOURNEY                         │
└─────────────────────────────────────────────────────────────────────┘

  ┌───────────────────┐
  │ Security mandate: │
  │ "All MCP configs  │
  │ must be audited"  │
  └─────────┬─────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 1: Add to GitHub Actions (5 minutes)               │
  │                                                          │
  │ .github/workflows/mcp-security.yml                      │
  │ ─────────────────────────────────                       │
  │ name: MCP Security Audit                                │
  │ on: [push, pull_request]                                │
  │ jobs:                                                    │
  │   audit:                                                 │
  │     runs-on: ubuntu-latest                              │
  │     steps:                                               │
  │       - uses: actions/checkout@v4                       │
  │       - name: MCP Security Check                        │
  │         run: npx mcp-shield --project --ci              │
  │              --sarif results.sarif                       │
  │       - uses: github/codeql-action/upload-sarif@v3      │
  │         with:                                            │
  │           sarif_file: results.sarif                     │
  └──────────────────────────┬───────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 2: Add config file to repo                         │
  │                                                          │
  │ .mcp-shield.yml                                         │
  │ ───────────────                                         │
  │ failOn: [critical, high]                                │
  │ ignore:                                                  │
  │   - DW-002           # we handle rate limits elsewhere  │
  │ trustedDomains:                                          │
  │   - api.internal.co  # our internal API                 │
  │ sourceAnalysis: true                                     │
  │ cveCheck: true                                           │
  └──────────────────────────┬───────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 3: Pipeline runs on every PR                       │
  │                                                          │
  │                                                          │
  │    Developer pushes          mcp-shield runs             │
  │    PR with new MCP    ────▶  --project --ci              │
  │    server in .mcp.json       scans only project config   │
  │                                                          │
  │         │                          │                     │
  │         │                ┌─────────┴──────────┐          │
  │         │                ▼                    ▼          │
  │         │         ┌────────────┐       ┌───────────┐    │
  │         │         │ Exit 0     │       │ Exit 1    │    │
  │         │         │ No crit/   │       │ Critical  │    │
  │         │         │ high found │       │ or high   │    │
  │         │         │            │       │ found     │    │
  │         │         │ ✅ PR      │       │ ❌ PR     │    │
  │         │         │ passes     │       │ blocked   │    │
  │         │         └────────────┘       └─────┬─────┘    │
  │         │                                    │          │
  │         │                                    ▼          │
  │         │                          SARIF uploaded to     │
  │         │                          GitHub Code Scanning  │
  │         │                          Findings appear as    │
  │         │                          annotations on the PR │
  │         │                                               │
  └─────────┴───────────────────────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ ONGOING: Rug-pull detection                             │
  │                                                          │
  │ mcp-shield stores snapshots of tool definitions.        │
  │ If a server's tools change between CI runs              │
  │ (e.g., npm update pulled a new version),                │
  │ TP-003 flags the diff as a potential rug-pull.          │
  │                                                          │
  │ Pipeline catches supply chain attacks automatically.    │
  └──────────────────────────────────────────────────────────┘
```

**Time to value:** 5 minutes to set up. Runs automatically forever after.

**What makes them come back:** It's invisible — runs in the background and only surfaces when something is wrong. The SARIF integration means findings show up as PR annotations, not a separate tool to check.

---

## Persona 4: Open-Source MCP Server Author Wanting a Trust Badge

**Who they are:** Developer who built an MCP server (e.g., a Notion integration, a weather API wrapper) and published it on npm. Wants users to trust their server. Wants to differentiate from sketchy community servers.

**Trigger:** Sees other MCP server READMEs with mcp-shield badges showing their trust grade. Wants the same credibility signal.

```
┌─────────────────────────────────────────────────────────────────────┐
│                 MCP SERVER AUTHOR JOURNEY                          │
└─────────────────────────────────────────────────────────────────────┘

  ┌───────────────────┐
  │ "I want users to  │
  │ trust my server"  │
  └─────────┬─────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 1: Audit their own server                          │
  │                                                          │
  │ cd my-mcp-server                                        │
  │ npx mcp-shield audit . --report                         │
  │                                                          │
  │ Scans tool definitions AND source code.                 │
  │ Author sees their own server through a security lens    │
  │ for the first time.                                     │
  └──────────────────────────┬───────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 2: Fix findings                                    │
  │                                                          │
  │ Common fixes for server authors:                        │
  │                                                          │
  │  SC-002 "SSRF: fetch() with unvalidated URL"            │
  │  → Add domain allowlist to fetch calls                  │
  │                                                          │
  │  SC-003 "Path traversal: fs.readFile with user input"   │
  │  → Add path.resolve() + startsWith() validation         │
  │                                                          │
  │  PE-003 "Server binds to 0.0.0.0"                       │
  │  → Change to 127.0.0.1                                  │
  │                                                          │
  │  PI-005 "Description too long (2,100 chars)"            │
  │  → Trim description, move docs to README                │
  └──────────────────────────┬───────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 3: Add to CI + get badge                           │
  │                                                          │
  │ Add mcp-shield to their GitHub Actions so every         │
  │ release is audited automatically.                       │
  │                                                          │
  │ Add badge to README:                                    │
  │                                                          │
  │ [![mcp-shield: A](https://img.shields.io/badge/        │
  │   mcp--shield-A-brightgreen)]                           │
  │                                                          │
  │ Users browsing npm or GitHub see the grade              │
  │ before deciding to install.                             │
  └──────────────────────────┬───────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────┐
  │ STEP 4: Published to public audit registry (v2)         │
  │                                                          │
  │ Their server's trust grade appears on the mcp-shield    │
  │ public registry. Users can look up any server's grade   │
  │ before installing:                                      │
  │                                                          │
  │   npx mcp-shield lookup @their/mcp-server               │
  │                                                          │
  │   @their/mcp-server                                     │
  │   Grade: A (96/100)                                     │
  │   Last audited: 2 days ago                              │
  │   0 findings                                            │
  │   Source: https://github.com/their/mcp-server           │
  │                                                          │
  │ This becomes the "npm audit" equivalent for MCP.        │
  └──────────────────────────────────────────────────────────┘
```

**Time to value:** 10-15 minutes (audit + fix + re-audit). Badge is permanent value.

**What makes them come back:** The badge is a competitive advantage. Servers with an A grade get installed more than servers without one. It becomes table stakes for serious MCP server authors.

---

## The Flywheel

All four journeys feed into each other:

```
                    ┌──────────────────────┐
                    │   SERVER AUTHORS     │
                    │   audit & badge      │
                    │   their servers      │
                    └──────────┬───────────┘
                               │
                      more servers graded
                               │
                               ▼
  ┌──────────────┐   ┌──────────────────────┐   ┌──────────────────┐
  │   DEVOPS     │   │    PUBLIC REGISTRY   │   │   SECURITY       │
  │   gates      │◀──│    becomes           │──▶│   ENGINEERS      │
  │   CI/CD on   │   │    authoritative     │   │   require grade  │
  │   mcp-shield │   │    trust source      │   │   for approval   │
  └──────┬───────┘   └──────────────────────┘   └────────┬─────────┘
         │                     ▲                         │
         │                     │                         │
         └─────────────────────┼─────────────────────────┘
                               │
                      more installs of
                      mcp-shield
                               │
                               ▼
                    ┌──────────────────────┐
                    │   SOLO DEVELOPERS    │
                    │   scan before        │
                    │   installing         │
                    └──────────────────────┘
```

**The network effect:** Every server that gets a badge makes mcp-shield more visible. Every CI pipeline that gates on mcp-shield makes the badge more valuable. Every developer who scans before installing creates demand for more servers to get badges.

---

*mcp-shield — user journeys v1.0 — March 2026*
