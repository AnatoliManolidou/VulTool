# VulTool — CTI-Aware Vulnerability Remediation Pipeline

A GitHub Action that monitors your dependencies against a live CTI feed, performs AST-based reachability analysis, uses an LLM to confirm exploitability, and autonomously generates and verifies application-level fixes.

## How It Works

```
C1 Ecosystem → C2 Advisories → C3 SBOM → C4 Filter → C5 Classifier → C6 Priority
→ C7 AST Analysis → C8 Purple Team Context → C9 LLM Exploit Analysis → C10 Fix & Verify
```

C1–C6 run on every invocation. C7–C10 require direct JavaScript/TypeScript usage in the codebase; C9–C10 additionally require an LLM API key.

---

## Setup

### 1. Repository settings

Two settings must be enabled on the target repository before any run:

**Settings → Actions → General → Workflow permissions:**
- Select **"Read and write permissions"**
- Check **"Allow GitHub Actions to create and approve pull requests"**

Without the second setting, auto-PR creation on `PATCH_CONFIRMED` will fail with a 403.

### 2. Secrets

| Secret | Required | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | Yes (automatic) | SBOM API, advisory GraphQL, issue/PR creation |
| `LLM_API_KEY` | No | OpenRouter API key — required for C9/C10 |
| `DISCORD_WEBHOOK_URL` | No | Pipeline notifications |

### 3. Workflow permissions

The calling workflow must declare:

```yaml
permissions:
  contents: write       # fix branch creation
  actions: write        # rescan workflow_dispatch trigger
  issues: write         # GitHub Issue creation
  pull-requests: write  # auto-PR on PATCH_CONFIRMED (rescan workflow only)
```

The main pipeline workflow needs all except `pull-requests: write`. The rescan workflow needs all four.

---

## Workflow Examples

### Main pipeline (`demo-feed.yml`)

```yaml
name: CTI Pipeline

on:
  schedule:
    - cron: '17 * * * *'
  workflow_dispatch:

jobs:
  run-analysis:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      actions: write
      issues: write
    steps:
      - uses: actions/checkout@v4

      - uses: AnatoliManolidou/VulTool@feature/demo-feed
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          llm_api_key: ${{ secrets.LLM_API_KEY }}
          severity_threshold: 'HIGH'
          discord_webhook_url: ${{ secrets.DISCORD_WEBHOOK_URL }}
          create_issue: 'true'
```

### Patch verification rescan (`rescan.yml`)

> **Note:** This file must exist on the repository's **default branch** for `workflow_dispatch` to work, regardless of which branch is being rescanned.

```yaml
name: VulTool — Patch Verification Re-scan

on:
  workflow_dispatch:
    inputs:
      ghsa_id:
        description: 'GHSA ID of the patched vulnerability to re-scan'
        required: true
      fix_branch:
        description: 'Branch containing the fix to verify'
        required: true
      create_issue:
        description: 'Open a GitHub Issue with the patch verdict'
        required: false
        default: 'false'

jobs:
  patch-verification:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      actions: write
      issues: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.fix_branch }}

      - uses: AnatoliManolidou/VulTool@feature/demo-feed
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          llm_api_key: ${{ secrets.LLM_API_KEY }}
          rescan_mode: 'true'
          rescan_ghsa_id: ${{ inputs.ghsa_id }}
          create_issue: ${{ inputs.create_issue }}
          discord_webhook_url: ${{ secrets.DISCORD_WEBHOOK_URL }}
```

---

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `github_token` | Yes | — | GitHub API token (use `secrets.GITHUB_TOKEN`) |
| `llm_api_key` | No | — | OpenRouter API key. Without it, pipeline runs C1–C8 only |
| `severity_threshold` | No | `HIGH` | Minimum severity: `LOW` / `MODERATE` / `HIGH` / `CRITICAL` |
| `demo_mode` | No | `false` | Use bundled advisory feed (56 entries; stratified sample of 25 per run — 2 guaranteed reachable, 23 guaranteed filler) instead of live GitHub feed |
| `rescan_mode` | No | `false` | Patch verification mode — re-scans one advisory on a fix branch |
| `rescan_ghsa_id` | No | — | GHSA ID to target in rescan mode |
| `auto_rescan` | No | `true` | Automatically trigger the rescan workflow after a fix branch is created |
| `watched_ghsa_ids` | No | — | Comma-separated GHSA IDs to always fetch regardless of feed position |
| `adjacent_risks` | No | `false` | Include secondary security findings spotted in the attack path |
| `discord_webhook_url` | No | — | Discord webhook URL for pipeline notifications |
| `create_issue` | No | `false` | Open GitHub Issues for each finding; on `PATCH_CONFIRMED` also auto-creates a pull request. Requires `issues: write` (and `pull-requests: write` in the rescan workflow) |

---

## Operating Modes

### Main mode

Runs the full C1–C10 pipeline. A state cache tracks seen GHSA IDs — subsequent runs skip already-processed advisories unless `demo_mode` is enabled. When a fix is generated and internally verified, the rescan workflow is triggered automatically on the fix branch (controlled by `auto_rescan`).

### Rescan (patch verification) mode

Triggered automatically by the main pipeline, or manually via `workflow_dispatch`. Runs C1–C9 on the fix branch and reports one of three verdicts:

| Verdict | Meaning |
|---|---|
| `PATCH_CONFIRMED` | Vulnerability no longer reachable in the patched code. Issue + PR opened if `create_issue: true`. |
| `PATCH_FAILED` | Vulnerability still exploitable after the fix. Issue opened for manual remediation. |
| `PATCH_INCONCLUSIVE` | LLM did not produce a definitive verdict (usually a timeout). Re-run to retry. |

---

## Notifications

Discord embeds are sent for every pipeline outcome: analysis complete (with per-threat verdict breakdown), patch verification result, and pipeline errors. Set `discord_webhook_url` to enable.

---

## Limitations

- **JavaScript/TypeScript only** for deep analysis (C7–C10). C1–C6 are multi-ecosystem.
- **Global middleware and client-side patterns** are not traced by the AST analyzer — vulnerabilities triggered inside middleware with no single traceable HTTP entry point (e.g. morgan, applied to every route) or in browser-side framework code (e.g. a React component) are not detected. Middleware registered via a per-route derived binding (e.g. `const upload = multer(...); app.post('/x', upload.any(), ...)`) *is* detected — the analyzer traces one level of variable assignment from the library's constructor call.
- **LLM non-determinism** — the same advisory and code can produce different verdicts across runs. Single-run verdicts should be treated as probabilistic.
- **Fix applier** replaces source text by exact match — may fail if the LLM reformats whitespace or if the function is dynamically constructed.
- **SBOM API deprecation** — the synchronous SBOM endpoint used by C3 is scheduled for removal on 2026-11-13.
