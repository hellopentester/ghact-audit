# GitHub Actions Supply Chain Audit Tool

A security operations Python script that audits GitHub Actions workflow runs for supply chain compromise — specifically detecting malicious npm package versions installed during CI/CD pipelines within a configurable time window.

Originally developed during an active supply chain incident response involving the malicious `axios` npm packages `1.14.1` and `0.30.4`.

---

## What It Does

The script runs three detection checks in sequence:

```
PHASE 1 — Repository Scan
  Search all package.json files in the target org(s)
  Flag any that declare a known malicious package version

PHASE 2 — Workflow Run Analysis (within time window)
  For every repo found in Phase 1:
    → Check all workflow runs in the time window
    → Per run: inspect every job and every step
    → CHECK A: Does the run have an actions/cache step?  (no cache = higher exposure)
    → CHECK B: Do the raw job logs show the malicious package being installed?
    → CHECK C: Does the run belong to a repo with a malicious package.json pin?

PHASE 3 — Output
  Print live summary to terminal
  Write 3 output files (JSON summary, JSON detail, PDF report)
```

### Detection Methods

| Check | Signal | How |
|---|---|---|
| **Static — package.json** | Malicious version pinned in source | Reads every `package.json` hit from GitHub code search |
| **Live — job logs** | Malicious version actually installed | Downloads raw job log text, scans every line with regex |
| **Exposure — no cache** | Packages fetched fresh from registry (higher risk window) | Checks for `actions/cache` step in all jobs |

---

## Output Files

| File | Contents |
|---|---|
| `audit_report.json` | Flagged items only — malicious repos, no-cache runs, log evidence |
| `audit_report_detail.json` | **Every** repo scanned + **every** run checked (including clean), with full job/step/log detail |
| `audit_report_summary.pdf` | Security operations style PDF report with risk rating, findings tables, IOC list, and recommendations |

### PDF Report Sections

1. Title banner with incident reference and classification
2. Executive Summary + colour-coded risk level (`LOW / MEDIUM / HIGH`)
3. Scan Scope table
4. Findings — static dependency analysis + workflow run analysis
5. Threat Indicators Checked (IOC table)
6. Flagged Repositories *(only shown if findings exist)*
7. Conclusion & Risk Assessment
8. Recommendations
9. Per-page footer with TLP classification and generation timestamp

---

## Requirements

- Python 3.10+
- A GitHub Personal Access Token (PAT)

### Token Scopes Required

| Scope | Why |
|---|---|
| `repo` (read) | Read repository contents and workflow run data |
| `read:org` | List repositories within an organisation |
| `actions:read` | Access workflow runs, jobs, and job logs |

> **Tip:** Use a fine-grained PAT scoped to only the target organisation with read-only permissions.

### Install Dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
requests>=2.28.0
fpdf2>=2.7.0
```

---

## Usage

### Quickstart

```bash
export GITHUB_TOKEN=ghp_your_token_here

python3 audit_workflows.py --orgs your-org
```

### Full Usage

```bash
python3 audit_workflows.py \
  --orgs your-org \
  --date 2026-03-31 \
  --package axios \
  --versions "1.14.1,0.30.4" \
  --window-start 08:00 \
  --window-end 12:30 \
  --incident "SECOPS-1234" \
  --output audit_report.json \
  --detail-json audit_report_detail.json \
  --pdf audit_report_summary.pdf \
  --verbose
```

### All Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--orgs` | **Yes** | — | Comma-separated GitHub org(s) to audit (e.g. `myorg,otherorg`) |
| `--date` | No | Today (SGT) | Date to audit in `YYYY-MM-DD` format |
| `--package` | No | `axios` | npm package name to scan for |
| `--versions` | No | `1.14.1,0.30.4` | Comma-separated malicious version(s) to flag |
| `--window-start` | No | `08:00` | Audit window start in HH:MM SGT (24h) |
| `--window-end` | No | `12:30` | Audit window end in HH:MM SGT (24h) |
| `--incident` | No | *(blank)* | Incident reference shown in reports (e.g. `SIRT-1234`) |
| `--output` | No | `audit_report.json` | Summary JSON output path |
| `--detail-json` | No | `audit_report_detail.json` | Full detail JSON output path |
| `--pdf` | No | `audit_report_summary.pdf` | PDF report output path |
| `--token` | No* | `$GITHUB_TOKEN` | GitHub PAT. Reads from env var if not passed |
| `--verbose` | No | `false` | Enable DEBUG logging |

> \* Token is required but can be supplied via the `GITHUB_TOKEN` environment variable.

---

## Examples

### Audit multiple orgs for today's window

```bash
python3 audit_workflows.py \
  --orgs org-one,org-two \
  --incident "MY-INCIDENT-001"
```

### Audit a specific date with a custom time window

```bash
python3 audit_workflows.py \
  --orgs my-org \
  --date 2026-03-31 \
  --window-start 09:00 \
  --window-end 18:00
```

### Scan for a different malicious package

```bash
python3 audit_workflows.py \
  --orgs my-org \
  --package lodash \
  --versions "4.17.4,4.17.15"
```

### Add a new malicious version without code changes

```bash
python3 audit_workflows.py \
  --orgs my-org \
  --package axios \
  --versions "1.14.1,0.30.4,2.0.1"
```

---

## Live Scan Output

The script prints real-time progress as it runs:

```
╔══════════════════════════════════════════════════════════════════════╗
║         GitHub Actions Supply Chain Audit — Live Scan         ║
╚══════════════════════════════════════════════════════════════════════╝
  Incident ref : SECOPS-1234
  Audit window : 2026-03-31 08:00 SGT  →  2026-03-31 12:30 SGT
  Orgs         : my-org

────────────────────────────────────────────────────────────────────────
  PHASE 1  ▶  Searching repositories for axios in package.json
────────────────────────────────────────────────────────────────────────
  Query : org:my-org "axios" filename:package.json
    Fetching results …
    · Page 1 → 53 item(s)  (cumulative: 53 / 53)
    Found 53 package.json file(s) referencing axios

[1/53]  📦  my-org/payments-service  (branch: main)
    ↳ Reading package.json …
      ↳ axios version spec : 1.14.1  →  ⚠️  MALICIOUS

────────────────────────────────────────────────────────────────────────
  PHASE 2  ▶  Scanning workflow runs  [08:00 – 12:30 SGT]
────────────────────────────────────────────────────────────────────────
  ┌──────────────────────────────────────┐
  │  [1/5]  my-org/payments-service     │
  └──────────────────────────────────────┘
  📦 axios  1.14.1   ⚠️  MALICIOUS  (package.json)
  🔍 Fetching workflow runs in window …
    → 2 run(s) found in window

    ▶ Run [1/2]  #11111
        Workflow : CI / Build & Test
        File     : .github/workflows/ci.yml
        Branch   : main   Event: push   Actor: alice
        ...
        🗃️ Cache action present : YES ✅
        🔎 Scanning job logs for malicious axios evidence …
          ┌─ Job: test  [completed / ✅ success]
               1. ✅ Checkout
               2. ✅ Restore cache  🗃️ [CACHE]
               3. ✅ npm ci
               4. ✅ Run tests
            🚨 axios@1.14.1 FOUND IN LOGS  (2 line(s))
              line    42: added axios@1.14.1 (1 package, 203 kB)
              line    43: + axios@1.14.1
```

---

## How the Log Scanner Works

After fetching each job's raw log text via the GitHub API, the scanner searches every line for patterns that indicate the malicious package was resolved or installed:

| Pattern | Covers |
|---|---|
| `axios@1.14.1` | npm v7+ install output, `npm ls`, `npm audit` |
| `axios 1.14.1` | yarn classic install output |
| `\baxios\b.*\b1\.14\.1\b` | pnpm and mixed format output |
| `"axios": ".*1.14.1` | lockfile snapshots printed in logs |

Patterns are built dynamically from `--versions` — no code change needed when adding new malicious versions.

---

## Report Risk Levels

| Risk | Condition |
|---|---|
| 🟢 **LOW** | No malicious version found in any `package.json` or job log |
| 🟠 **MEDIUM** | Malicious version found in `package.json` but not confirmed in job logs |
| 🔴 **HIGH** | Malicious version confirmed in workflow job logs (actual installation evidence) |

---

## Security Notes

- **Token safety:** The PAT is only used in the `Authorization` HTTP header. It is never logged, printed to stdout, or written to any output file.
- **TLS:** All GitHub API calls use `requests` with certificate validation enabled (default).
- **Path traversal protection:** Output file paths (`--output`, `--detail-json`, `--pdf`) are validated to stay within the current working directory. Absolute paths and `../` traversal are rejected.
- **No shell execution:** The script never calls `subprocess`, `os.system`, `eval`, or `exec`.
- **Input sanitization:** GitHub API error responses are sanitized before display (only `code` and `message` fields are extracted).
- **Archived repos:** Excluded from results at the API response level since `NOT is:archived` is not a valid code search qualifier.

---

## Project Structure

```
.
├── audit_workflows.py       # Main script
├── requirements.txt         # Python dependencies
├── README.md                # This file
└── (generated at runtime)
    ├── audit_report.json         # Summary — flagged items only
    ├── audit_report_detail.json  # Full detail — all repos and runs
    └── audit_report_summary.pdf  # PDF security operations report
```

---

## Contributing

To flag additional malicious package versions without modifying code, use `--versions`:

```bash
--versions "1.14.1,0.30.4,<new_version>"
```

To permanently add a version to the defaults, update `MALICIOUS_VERSIONS` at the top of `audit_workflows.py`:

```python
MALICIOUS_VERSIONS = {"1.14.1", "0.30.4", "<new_version>"}
```

---

## License

MIT
