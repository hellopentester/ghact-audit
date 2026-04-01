#!/usr/bin/env python3
"""
GitHub Actions Workflow Security Audit Script
==============================================
Incident: SECOPS-1234

Checks within the time window 8:00 AM – 12:30 PM SGT (00:00 – 04:30 UTC):
  1. Workflow runs that have NO cache hit  (no `actions/cache` step found in any job)
  2. Repositories whose package.json references a malicious axios version
       (currently flagged: 1.14.1, 0.30.4)
  3. Any workflow run that pulled/installed a malicious axios version during that window

Usage:
  export GITHUB_TOKEN=ghp_...
  python audit_workflows.py [--date YYYY-MM-DD] [--orgs org1,org2] [--output report.json]

Requirements:
  pip install requests
"""

import os
import sys
import json
import logging
import argparse
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Malicious npm package versions to flag — overridden at runtime by --package / --versions
MALICIOUS_PACKAGE  = "axios"
MALICIOUS_VERSIONS = {"1.14.1", "0.30.4"}

# Audit time window (SGT) — overridden at runtime by --window-start / --window-end
SGT = timezone(timedelta(hours=8))
SGT_WINDOW_START = (8,  0)   # 08:00 SGT
SGT_WINDOW_END   = (12, 30)  # 12:30 SGT

GITHUB_API = "https://api.github.com"

# actions/cache step identifiers in workflow job steps
CACHE_ACTION_NAMES = {"actions/cache", "actions/cache@"}

# How long to wait (seconds) between paginated calls to avoid secondary rate-limits
REQUEST_DELAY = 0.3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("secops-1234")


# ---------------------------------------------------------------------------
# GitHub API client
# ---------------------------------------------------------------------------

class GitHubClient:
    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _get(self, url: str, params: Optional[dict] = None, retries: int = 3) -> dict | list:
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.get(url, params=params, timeout=30)
            except requests.RequestException as exc:
                log.warning("Network error (attempt %d/%d): %s", attempt, retries, exc)
                time.sleep(2 ** attempt)
                continue

            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset_ts - int(time.time()), 5)
                log.warning("Rate-limited. Sleeping %d seconds …", wait)
                time.sleep(wait)
                continue

            if resp.status_code == 404:
                return {}

            if resp.status_code == 422:
                # Unprocessable Entity — usually an invalid search query
                body = resp.json() if resp.content else {}
                # Sanitize: only extract code+message fields, not raw error objects
                raw_errors = body.get("errors") or []
                safe_errors = [
                    {"code": e.get("code", "unknown"), "message": e.get("message", "")}
                    if isinstance(e, dict) else str(e)
                    for e in raw_errors
                ] or body.get("message", "unknown error")
                raise ValueError(f"GitHub API 422 (invalid query?) — {safe_errors}")

            resp.raise_for_status()
            time.sleep(REQUEST_DELAY)
            return resp.json()

        raise RuntimeError(f"Failed to GET {url} after {retries} attempts")

    def paginate(self, url: str, params: Optional[dict] = None) -> list:
        """Yield all items across paginated results."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        page = 1
        results = []
        while True:
            params["page"] = page
            data = self._get(url, params)
            # API may return a dict with a list inside, or a bare list
            items = data if isinstance(data, list) else data.get("items") or data.get("workflow_runs") or data.get("jobs") or []
            if not items:
                break
            results.extend(items)
            if len(items) < params["per_page"]:
                break
            page += 1
        return results

    def search_code(self, query: str) -> list:
        """Search code across GitHub (handles pagination up to 1000 results)."""
        url = f"{GITHUB_API}/search/code"
        params = {"q": query, "per_page": 100}
        results = []
        page = 1
        while True:
            params["page"] = page
            data = self._get(url, params)

            # Surface API-level errors immediately
            if data.get("message"):
                raise RuntimeError(
                    f"GitHub Search API error: {data['message']}\n"
                    f"  Errors: {data.get('errors', [])}\n"
                    f"  Query : {query}"
                )

            total   = data.get("total_count", 0)
            items   = data.get("items", [])
            results.extend(items)

            sp(f"  Page {page} → {len(items)} item(s)  "
               f"(cumulative: {len(results)} / {total})", indent=2, marker="·")

            # Stop when last page reached
            if not items or len(items) < 100 or len(results) >= total:
                break
            page += 1
            time.sleep(1)  # extra pause between search pages to avoid secondary rate-limit
        return results

    def get_file_content(self, owner: str, repo: str, path: str, ref: str = "") -> Optional[str]:
        """Return decoded text content of a file, or None on error."""
        import base64
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref} if ref else {}
        data = self._get(url, params)
        if not data or data.get("encoding") != "base64":
            return None
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None

    def list_workflow_runs(self, owner: str, repo: str,
                           created_after: datetime, created_before: datetime) -> list:
        """
        Return workflow runs whose created_at falls within [created_after, created_before].
        GitHub 'created' filter format: YYYY-MM-DDTHH:MM:SS..YYYY-MM-DDTHH:MM:SS
        """
        url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/runs"
        # GitHub API accepts ISO8601 range in 'created' query param
        created_range = (
            f"{created_after.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            f"..{created_before.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        params = {"per_page": 100, "created": created_range}
        runs = []
        page = 1
        while True:
            params["page"] = page
            data = self._get(url, params)
            items = data.get("workflow_runs", [])
            runs.extend(items)
            if len(items) < 100:
                break
            page += 1
        return runs

    def list_run_jobs(self, owner: str, repo: str, run_id: int) -> list:
        url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/runs/{run_id}/jobs"
        params = {"filter": "all", "per_page": 100}
        data = self._get(url, params)
        return data.get("jobs", [])

    def get_job_logs(self, owner: str, repo: str, job_id: int) -> str:
        """
        Fetch the raw text log for a single job.
        The API returns a redirect to a storage URL; requests follows it automatically.
        Returns the log text, or empty string on failure.
        """
        url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
        for attempt in range(1, 4):
            try:
                resp = self.session.get(url, timeout=60, allow_redirects=True)
            except requests.RequestException as exc:
                log.warning("Log fetch error (attempt %d): %s", attempt, exc)
                time.sleep(2 ** attempt)
                continue

            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset_ts - int(time.time()), 5)
                log.warning("Rate-limited on log fetch. Sleeping %d s …", wait)
                time.sleep(wait)
                continue

            if resp.status_code in (404, 410):
                # 410 Gone = logs expired (>90 days)
                return ""

            if resp.status_code == 200:
                time.sleep(REQUEST_DELAY)
                return resp.text

            log.warning("Unexpected status %d fetching logs for job %d", resp.status_code, job_id)
            return ""

        return ""

    def get_workflow(self, owner: str, repo: str, workflow_id) -> dict:
        """Return workflow metadata (name, path, state)."""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/workflows/{workflow_id}"
        data = self._get(url)
        return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Time window helpers
# ---------------------------------------------------------------------------

def build_utc_window(date_str: Optional[str] = None) -> tuple[datetime, datetime]:
    """
    Return (start_utc, end_utc) for the SGT 08:00–12:30 window on the given
    date (defaults to today in SGT).
    """
    if date_str:
        base = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=SGT)
    else:
        base = datetime.now(SGT).replace(hour=0, minute=0, second=0, microsecond=0)

    start_sgt = base.replace(hour=SGT_WINDOW_START[0], minute=SGT_WINDOW_START[1], second=0)
    end_sgt   = base.replace(hour=SGT_WINDOW_END[0],   minute=SGT_WINDOW_END[1],   second=0)

    return start_sgt.astimezone(timezone.utc), end_sgt.astimezone(timezone.utc)


def fmt_sgt(dt_str: str) -> str:
    """Convert ISO8601 UTC string from API to human-readable SGT string."""
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.astimezone(SGT).strftime("%Y-%m-%d %H:%M:%S SGT")
    except Exception:
        return dt_str


# ---------------------------------------------------------------------------
# Core detection logic
# ---------------------------------------------------------------------------

def run_uses_cache(jobs: list) -> bool:
    """Return True if ANY job step uses actions/cache."""
    for job in jobs:
        for step in job.get("steps", []):
            uses = step.get("uses", "") or ""
            name = step.get("name", "").lower()
            if uses.startswith("actions/cache") or "actions/cache" in uses:
                return True
            if "cache" in name and "restore" in name:
                return True
    return False


def duration_str(started: str, completed: str) -> str:
    """Return human-readable duration between two ISO8601 timestamps."""
    try:
        s = datetime.fromisoformat(started.replace("Z", "+00:00"))
        e = datetime.fromisoformat(completed.replace("Z", "+00:00"))
        secs = int((e - s).total_seconds())
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"
    except Exception:
        return "—"


def extract_job_details(jobs: list) -> list:
    """Return a structured list of job cards with per-step information."""
    result = []
    for job in jobs:
        steps = []
        for step in job.get("steps", []):
            steps.append({
                "number":       step.get("number"),
                "name":         step.get("name", ""),
                "status":       step.get("status", ""),
                "conclusion":   step.get("conclusion", ""),
                "started_at":   step.get("started_at", ""),
                "completed_at": step.get("completed_at", ""),
                "uses_cache":   (
                    "actions/cache" in (step.get("uses", "") or "")
                    or ("cache" in step.get("name", "").lower()
                        and "restore" in step.get("name", "").lower())
                ),
            })
        result.append({
            "job_id":       job.get("id"),
            "job_name":     job.get("name", ""),
            "status":       job.get("status", ""),
            "conclusion":   job.get("conclusion", ""),
            "runner_name":  job.get("runner_name", ""),
            "runner_group": job.get("runner_group_name", ""),
            "started_at":   job.get("started_at", ""),
            "completed_at": job.get("completed_at", ""),
            "duration":     duration_str(
                                job.get("started_at", ""),
                                job.get("completed_at", ""),
                            ),
            "html_url":     job.get("html_url", ""),
            "steps":        steps,
        })
    return result


# ---------------------------------------------------------------------------
# Log scanning for malicious package evidence
# ---------------------------------------------------------------------------



# Patterns that indicate a malicious axios version was resolved/installed in a step log.
# Generated dynamically from MALICIOUS_VERSIONS so adding a version above is enough.
# Covers npm v6, npm v7+, yarn classic, yarn berry, pnpm output formats.
def _build_log_patterns():
    import re
    patterns = []
    for ver in MALICIOUS_VERSIONS:
        escaped = re.escape(ver)
        patterns += [
            re.compile(rf'axios@{escaped}',              re.IGNORECASE),  # npm / pnpm
            re.compile(rf'axios\s+{escaped}',            re.IGNORECASE),  # yarn classic
            re.compile(rf'\baxios\b.*\b{escaped}\b',     re.IGNORECASE),  # generic
            re.compile(rf'"axios":\s*".*{escaped}',      re.IGNORECASE),  # lock snapshots
        ]
    return patterns

_AXIOS_LOG_PATTERNS = _build_log_patterns()


def scan_log_for_malicious_axios(log_text: str) -> list[dict]:
    """
    Scan raw job log text for evidence of a malicious axios version being
    installed or resolved.  Returns up to 20 match dicts per job.
    """
    matches = []
    for lineno, line in enumerate(log_text.splitlines(), 1):
        for pat in _AXIOS_LOG_PATTERNS:
            if pat.search(line):
                matches.append({
                    "line_number": lineno,
                    "line":        line.strip()[:200],
                    "pattern":     pat.pattern,
                })
                break  # one entry per line is enough
        if len(matches) >= 20:
            break
    return matches
    """
    Parse package.json and return the axios version string if present,
    else None.
    """
    try:
        pkg = json.loads(pkg_content)
    except json.JSONDecodeError:
        return None

    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = pkg.get(section, {})
        if "axios" in deps:
            return deps["axios"]
    return None


def is_malicious_version(version_spec: str) -> bool:
    """
    Return True if the version spec pins to any known malicious version.
    Handles plain "1.14.1", "=1.14.1", "^1.14.1", "~1.14.1" etc.
    """
    v = version_spec.strip().lstrip("^~=v").strip()
    return v in MALICIOUS_VERSIONS


def parse_axios_version(pkg_content: str) -> Optional[str]:
    """
    Parse package.json text and return the axios version string if present,
    else None.  Checks all dependency sections.
    """
    try:
        pkg = json.loads(pkg_content)
    except json.JSONDecodeError:
        return None

    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = pkg.get(section, {})
        if "axios" in deps:
            return deps["axios"]
    return None


# ---------------------------------------------------------------------------
# Live scan printer  (writes directly to stdout, unbuffered)
# ---------------------------------------------------------------------------

def sp(msg: str = "", indent: int = 0, marker: str = ""):
    """Print a live scan progress line immediately (unbuffered)."""
    prefix = "  " * indent
    if marker:
        prefix += marker + " "
    print(f"{prefix}{msg}", flush=True)


def sp_phase(title: str, phase_num: int):
    bar = "─" * 72
    print(f"\n{bar}", flush=True)
    print(f"  PHASE {phase_num}  ▶  {title}", flush=True)
    print(f"{bar}", flush=True)


def sp_repo_header(repo_full: str, idx: int, total: int):
    print(f"\n  ┌{'─' * 68}┐", flush=True)
    print(f"  │  [{idx}/{total}]  {repo_full:<60}  │", flush=True)
    print(f"  └{'─' * 68}┘", flush=True)


# ---------------------------------------------------------------------------
# Main audit routine
# ---------------------------------------------------------------------------

def audit(orgs: list[str], date_str: Optional[str], gh: GitHubClient,
          incident: str = "") -> dict:
    start_utc, end_utc = build_utc_window(date_str)

    sp()
    sp("╔══════════════════════════════════════════════════════════════════════╗")
    sp("║         GitHub Actions Axios Supply Chain Audit — Live Scan         ║")
    sp("╚══════════════════════════════════════════════════════════════════════╝")
    if incident:
        sp(f"  Incident ref : {incident}")
    sp(f"  Audit window : {start_utc.astimezone(SGT).strftime('%Y-%m-%d %H:%M SGT')}  →  "
       f"{end_utc.astimezone(SGT).strftime('%Y-%m-%d %H:%M SGT')}")
    sp(f"  Orgs         : {', '.join(orgs)}")
    sp(f"  Target pkg   : {MALICIOUS_PACKAGE}  malicious versions: {', '.join(sorted(MALICIOUS_VERSIONS))}  (known malicious)")

    report = {
        "audit_window": {
            "start_sgt": start_utc.astimezone(SGT).isoformat(),
            "end_sgt":   end_utc.astimezone(SGT).isoformat(),
            "start_utc": start_utc.isoformat(),
            "end_utc":   end_utc.isoformat(),
        },
        "malicious_package":   MALICIOUS_PACKAGE,
        "malicious_versions":  sorted(MALICIOUS_VERSIONS),
        "orgs": orgs,
        "incident": incident,
        "repos_with_malicious_axios": [],
        "workflow_runs_no_cache": [],
        "workflow_runs_axios_in_logs": [],
        "workflow_runs_malicious_axios_repo": [],
        # full detail lists (every repo and every run, not just flagged ones)
        "all_repos_scanned": [],
        "all_runs_checked":  [],
        "summary": {},
    }

    # -----------------------------------------------------------------------
    # PHASE 1 – Discover repos that reference axios in package.json
    # -----------------------------------------------------------------------
    sp_phase("Searching repositories for axios in package.json", 1)

    axios_repos: dict[str, dict] = {}

    for org in orgs:
        # filename:package.json  — correct REST API qualifier (path:**/ glob not supported)
        # Archived repo filtering is done post-fetch via the repository.archived flag
        # because `NOT is:archived` is only valid in repository/issue search, not code search
        query = f'org:{org} "axios" filename:package.json'
        sp(f"  Query : {query}")
        sp(f"  Fetching results …", indent=1)
        hits = gh.search_code(query)
        sp(f"  Found {len(hits)} package.json file(s) referencing axios", indent=1)
        sp()

        seen_repos_in_org: set[str] = set()

        for idx, hit in enumerate(hits, 1):
            repo_full = hit["repository"]["full_name"]
            owner, repo = repo_full.split("/", 1)
            pkg_path = hit.get("path", "package.json")
            default_branch = hit["repository"].get("default_branch", "")

            # Skip archived repos (NOT is:archived can't be used in code search API)
            if hit["repository"].get("archived", False):
                sp(f"[{idx}/{len(hits)}]  ⏭️  {repo_full}  — archived, skipping")
                continue

            repo_tag = f"[{idx}/{len(hits)}]"
            if repo_full not in seen_repos_in_org:
                seen_repos_in_org.add(repo_full)
                sp(f"{repo_tag}  📦  {repo_full}  (branch: {default_branch or 'default'})")
            else:
                sp(f"{repo_tag}  📦  {repo_full}  (additional package.json)")

            sp(f"Reading {pkg_path} …", indent=2, marker="↳")

            content = gh.get_file_content(owner, repo, pkg_path)
            if content is None:
                sp(f"Could not read file — skipping", indent=3, marker="⚠️")
                continue

            version_spec = parse_axios_version(content)
            if version_spec is None:
                sp(f"axios key not present in {pkg_path} — skipping", indent=3, marker="·")
                continue

            malicious = is_malicious_version(version_spec)
            flag      = "⚠️  MALICIOUS" if malicious else "✅ safe"
            sp(f"axios version spec : {version_spec}  →  {flag}", indent=3, marker="↳")

            entry = {
                "repo":              repo_full,
                "pkg_path":          pkg_path,
                "axios_version_spec": version_spec,
                "malicious":         malicious,
            }
            key = f"{repo_full}::{pkg_path}"
            if key not in axios_repos:
                axios_repos[key] = entry
                report["all_repos_scanned"].append(entry)
                if malicious:
                    report["repos_with_malicious_axios"].append(entry)

    unique_repos: list[str] = sorted({v["repo"] for v in axios_repos.values()})
    sp()
    sp(f"  Unique repos with axios in package.json : {len(unique_repos)}")
    sp(f"  Repos with MALICIOUS axios              : "
       f"{len(report['repos_with_malicious_axios'])}")

    # -----------------------------------------------------------------------
    # PHASE 2 – Check workflow runs in the time window for each repo
    # -----------------------------------------------------------------------
    sp_phase(
        f"Scanning workflow runs  [{start_utc.astimezone(SGT).strftime('%H:%M')} – "
        f"{end_utc.astimezone(SGT).strftime('%H:%M')} SGT]  across {len(unique_repos)} repo(s)",
        2,
    )

    for repo_idx, repo_full in enumerate(unique_repos, 1):
        owner, repo = repo_full.split("/", 1)

        sp_repo_header(repo_full, repo_idx, len(unique_repos))

        # Axios status for this repo
        repo_axios_entries = [
            e for k, e in axios_repos.items()
            if k.startswith(repo_full + "::")
        ]
        for ae in repo_axios_entries:
            mal_tag = "⚠️  MALICIOUS" if ae["malicious"] else "✅ safe"
            sp(f"axios  {ae['axios_version_spec']:12s}  {mal_tag}  ({ae['pkg_path']})",
               indent=1, marker="📦")

        sp(f"Fetching workflow runs in window …", indent=1, marker="🔍")
        runs = gh.list_workflow_runs(owner, repo, start_utc, end_utc)

        if not runs:
            sp(f"No workflow runs found in the audit window.", indent=2, marker="·")
            continue

        sp(f"{len(runs)} run(s) found in window", indent=2, marker="→")

        for run_idx, run in enumerate(runs, 1):
            run_id        = run["id"]
            run_name      = run.get("name") or str(run.get("workflow_id", "unknown"))
            run_url       = run.get("html_url", "")
            created       = run.get("created_at", "")
            updated       = run.get("updated_at", "")
            run_started   = run.get("run_started_at", created)
            status        = run.get("status", "")
            conclusion    = run.get("conclusion", "")
            branch        = run.get("head_branch", "")
            event         = run.get("event", "")
            actor         = (run.get("actor") or {}).get("login", "")
            trigger_actor = (run.get("triggering_actor") or {}).get("login", actor)
            head_sha      = run.get("head_sha", "")[:12]
            head_msg      = (run.get("head_commit") or {}).get("message", "").split("\n")[0]
            head_author   = ((run.get("head_commit") or {}).get("author") or {}).get("name", "")
            workflow_id   = run.get("workflow_id", "")
            workflow_path = run.get("path", "")

            sp()
            sp(f"Run [{run_idx}/{len(runs)}]  #{run_id}", indent=2, marker="▶")
            sp(f"Workflow : {run_name}", indent=4)

            # Fetch workflow file path
            if not workflow_path and workflow_id:
                wf_meta = gh.get_workflow(owner, repo, workflow_id)
                workflow_path = wf_meta.get("path", "")
            sp(f"File     : {workflow_path or '(unknown)'}", indent=4)
            sp(f"Branch   : {branch}   Event: {event}   Actor: {actor}", indent=4)
            sp(f"Commit   : {head_sha}  by {head_author}  — {head_msg[:60]}", indent=4)
            sp(f"Status   : {status} / {_conclude_icon(conclusion)} {conclusion or 'in-progress'}",
               indent=4)
            sp(f"Started  : {fmt_sgt(run_started)}  →  {fmt_sgt(updated)}  "
               f"({duration_str(run_started, updated)})", indent=4)
            sp(f"URL      : {run_url}", indent=4)

            # Fetch jobs
            sp(f"Fetching jobs …", indent=4, marker="🔍")
            jobs        = gh.list_run_jobs(owner, repo, run_id)
            has_cache   = run_uses_cache(jobs)
            job_details = extract_job_details(jobs)

            cache_tag = "YES ✅" if has_cache else "NO ❌  ← FLAGGED"
            sp(f"Cache action present : {cache_tag}", indent=4, marker="🗃️")

            # ── Per-job: fetch logs and scan for malicious axios evidence ────
            sp(f"Scanning job logs for malicious axios evidence "
               f"({', '.join(sorted(MALICIOUS_VERSIONS))}) …",
               indent=4, marker="🔎")

            run_has_axios_in_logs = False
            for job in job_details:
                j_icon = _conclude_icon(job.get("conclusion", ""))
                sp(f"Job: {job['job_name']}  [{job['status']} / {j_icon} "
                   f"{job.get('conclusion', 'in-progress')}]  "
                   f"runner: {job.get('runner_name') or '(unknown)'}  "
                   f"duration: {job.get('duration', '—')}",
                   indent=5, marker="┌─")

                for step in job.get("steps", []):
                    s_icon         = _conclude_icon(step.get("conclusion", ""))
                    cache_tag_step = "  🗃️ [CACHE]" if step.get("uses_cache") else ""
                    sp(f"{step.get('number', '?'):>2}. {s_icon} {step['name']}{cache_tag_step}",
                       indent=7)

                # Fetch this job's log and scan it
                job_id   = job.get("job_id")
                log_text = gh.get_job_logs(owner, repo, job_id) if job_id else ""

                if not log_text:
                    sp(f"(log unavailable or empty)", indent=7, marker="·")
                    job["axios_log_matches"] = []
                else:
                    matches = scan_log_for_malicious_axios(log_text)
                    job["axios_log_matches"] = matches
                    if matches:
                        run_has_axios_in_logs = True
                        sp(f"⚠️  MALICIOUS axios FOUND IN LOGS  "
                           f"({len(matches)} line(s))", indent=7, marker="🚨")
                        for m in matches:
                            sp(f"  line {m['line_number']:>5}: {m['line']}", indent=8)
                    else:
                        sp(f"malicious axios not found in log", indent=7, marker="✅")

            run_entry = {
                "repo":               repo_full,
                "run_id":             run_id,
                "workflow_name":      run_name,
                "workflow_file":      workflow_path,
                "branch":             branch,
                "event":              event,
                "actor":              actor,
                "triggering_actor":   trigger_actor,
                "head_sha":           head_sha,
                "head_commit_msg":    head_msg,
                "head_commit_author": head_author,
                "status":             status,
                "conclusion":         conclusion,
                "created_at_sgt":     fmt_sgt(created),
                "updated_at_sgt":     fmt_sgt(updated),
                "run_started_sgt":    fmt_sgt(run_started),
                "duration":           duration_str(run_started, updated),
                "html_url":           run_url,
                "has_cache_action":   has_cache,
                "axios_found_in_logs": run_has_axios_in_logs,
                "job_count":          len(jobs),
                "jobs":               job_details,
            }

            if not has_cache:
                sp(f"-> Added to NO-CACHE findings", indent=4, marker="[RED]")
                report["workflow_runs_no_cache"].append(run_entry)

            if run_has_axios_in_logs:
                sp(f"-> Added to AXIOS-IN-LOGS findings", indent=4, marker="[ALERT]")
                report["workflow_runs_axios_in_logs"].append(run_entry)

            if any(e["malicious"] for e in repo_axios_entries):
                sp(f"-> Added to MALICIOUS-AXIOS-REPO findings", indent=4, marker="[ALERT]")
                report["workflow_runs_malicious_axios_repo"].append({
                    **run_entry,
                    "axios_findings": repo_axios_entries,
                })

            # always record to full detail list
            report["all_runs_checked"].append({
                **run_entry,
                "flagged_no_cache":      not has_cache,
                "flagged_axios_in_logs": run_has_axios_in_logs,
                "flagged_malicious_repo": any(e["malicious"] for e in repo_axios_entries),
                "axios_pkg_findings":    repo_axios_entries,
            })

    # -----------------------------------------------------------------------
    # PHASE 3 – Wrap up
    # -----------------------------------------------------------------------
    sp_phase("Scan complete", 3)
    report["summary"] = {
        "total_repos_scanned":                  len(unique_repos),
        "repos_with_malicious_axios_count":     len(report["repos_with_malicious_axios"]),
        "workflow_runs_no_cache_count":          len(report["workflow_runs_no_cache"]),
        "workflow_runs_axios_found_in_logs":     len(report["workflow_runs_axios_in_logs"]),
        "workflow_runs_in_malicious_repos":      len(report["workflow_runs_malicious_axios_repo"]),
    }
    s = report["summary"]
    sp(f"  Repos scanned                           : {s['total_repos_scanned']}")
    sp(f"  Repos with malicious axios              : {s['repos_with_malicious_axios_count']}")
    sp(f"  Workflow runs with NO cache action      : {s['workflow_runs_no_cache_count']}")
    sp(f"  Workflow runs w/ malicious axios in logs  : {s['workflow_runs_axios_found_in_logs']}")
    sp(f"  Workflow runs in malicious-axios repos  : {s['workflow_runs_in_malicious_repos']}")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="GitHub Actions Axios Supply Chain Audit Tool."
    )
    p.add_argument(
        "--date", metavar="YYYY-MM-DD",
        help="Date to audit (SGT). Defaults to today (SGT).",
    )
    p.add_argument(
        "--package", default="axios",
        help="npm package name to scan for (default: axios).",
    )
    p.add_argument(
        "--versions", default="1.14.1,0.30.4",
        help="Comma-separated malicious version(s) to flag (default: 1.14.1,0.30.4).",
    )
    p.add_argument(
        "--window-start", default="08:00", dest="window_start",
        metavar="HH:MM",
        help="Audit window start time in SGT, 24h format (default: 08:00).",
    )
    p.add_argument(
        "--window-end", default="12:30", dest="window_end",
        metavar="HH:MM",
        help="Audit window end time in SGT, 24h format (default: 12:30).",
    )
    p.add_argument(
        "--orgs", required=True,
        help="Comma-separated list of GitHub orgs to audit (e.g. myorg,anotherorg). Required.",
    )
    p.add_argument(
        "--incident", default="",
        help="Optional incident reference label shown in reports (e.g. SECOPS-1234).",
    )
    p.add_argument(
        "--output", default="audit_report.json",
        help="Path to write the summary JSON report (default: audit_report.json).",
    )
    p.add_argument(
        "--detail-json", default="audit_report_detail.json",
        dest="detail_json",
        help="Path to write the full detail JSON (default: audit_report_detail.json).",
    )
    p.add_argument(
        "--pdf", default="audit_report_summary.pdf",
        dest="pdf",
        help="Path to write the PDF summary report (default: audit_report_summary.pdf).",
    )
    p.add_argument(
        "--token", default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub personal access token (or set GITHUB_TOKEN env var).",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG logging.",
    )
    return p.parse_args()


def safe_output_path(raw: str, default_name: str) -> str:
    """
    Prevent path traversal on output file arguments.
    Accepts only bare filenames or paths within the current working directory.
    Raises SystemExit with a clear message if the resolved path escapes cwd.
    """
    resolved = os.path.realpath(os.path.abspath(raw))
    cwd      = os.path.realpath(os.getcwd())
    if not resolved.startswith(cwd + os.sep) and resolved != cwd:
        sys.exit(
            f"ERROR: Output path '{raw}' resolves outside the current directory.\n"
            f"  Resolved : {resolved}\n"
            f"  Allowed  : {cwd}/<filename>\n"
            f"Use a plain filename (e.g. --output {default_name})."
        )
    return resolved


def _conclude_icon(conclusion: str) -> str:
    return {
        "success":   "✅",
        "failure":   "❌",
        "cancelled": "⛔",
        "skipped":   "⏭️",
        "timed_out": "⏱️",
    }.get(conclusion, "⏳")


def _print_run_card(r: dict, label: str):
    """Print a detailed card for a single workflow run."""
    icon = _conclude_icon(r.get("conclusion", ""))
    print(f"\n  {'─' * 70}")
    print(f"  {label}")
    print(f"  {'─' * 70}")
    print(f"  Repository      : {r['repo']}")
    print(f"  Workflow name   : {r['workflow_name']}")
    print(f"  Workflow file   : {r.get('workflow_file') or '(unknown)'}")
    print(f"  Branch          : {r.get('branch', '')}")
    print(f"  Event           : {r.get('event', '')}")
    print(f"  Actor           : {r.get('actor', '')}  (triggered by: {r.get('triggering_actor', '')})")
    print(f"  Commit          : {r.get('head_sha', '')}  by {r.get('head_commit_author', '')}")
    print(f"  Commit message  : {r.get('head_commit_msg', '')}")
    print(f"  Status          : {r.get('status', '')}  /  {icon} {r.get('conclusion', 'in progress')}")
    print(f"  Started (SGT)   : {r.get('run_started_sgt', r.get('created_at_sgt', ''))}")
    print(f"  Updated (SGT)   : {r.get('updated_at_sgt', '')}")
    print(f"  Duration        : {r.get('duration', '—')}")
    print(f"  Has cache action: {'YES ✅' if r.get('has_cache_action') else 'NO ❌'}")
    print(f"  Run URL         : {r.get('html_url', '')}")
    print(f"  Jobs ({r.get('job_count', 0)}):")

    for job in r.get("jobs", []):
        j_icon = _conclude_icon(job.get("conclusion", ""))
        log_matches = job.get("axios_log_matches", [])
        log_tag = f"  🚨 MALICIOUS axios IN LOGS ({len(log_matches)} line(s))" \
                  if log_matches else ""
        print(f"    ┌─ Job: {job['job_name']}{log_tag}")
        print(f"    │  Status    : {job['status']} / {j_icon} {job.get('conclusion', 'in progress')}")
        print(f"    │  Runner    : {job.get('runner_name') or '(unknown)'}  "
              f"[{job.get('runner_group') or 'default'}]")
        print(f"    │  Duration  : {job.get('duration', '—')}")
        print(f"    │  Job URL   : {job.get('html_url', '')}")
        steps = job.get("steps", [])
        if steps:
            print(f"    │  Steps ({len(steps)}):")
            for step in steps:
                s_icon = _conclude_icon(step.get("conclusion", ""))
                cache_tag = " 🗃️ [CACHE]" if step.get("uses_cache") else ""
                print(f"    │    {step.get('number', '?'):>2}. {s_icon} {step['name']}{cache_tag}")
        if log_matches:
            print(f"    │  Log evidence ({len(log_matches)} line(s)):")
            for m in log_matches:
                print(f"    │    line {m['line_number']:>5}: {m['line']}")
        print(f"    └{'─' * 50}")

    # Malicious axios findings (only present in cross-ref list)
    if r.get("axios_findings"):
        print(f"  ⚠️  Malicious axios findings:")
        for af in r["axios_findings"]:
            print(f"      • {af['pkg_path']}  →  axios@{af['axios_version_spec']}")


def print_summary(report: dict):
    s        = report["summary"]
    incident = report.get("incident", "")
    label    = f"  {incident} — " if incident else "  "

    W = 74
    print("\n" + "╔" + "═" * W + "╗")
    print("║" + f"{label}GitHub Actions Security Audit Report".center(W) + "║")
    print("╚" + "═" * W + "╝")
    print(f"\n  Audit window  : {report['audit_window']['start_sgt']}")
    print(f"                  → {report['audit_window']['end_sgt']}")
    print(f"  Orgs audited  : {', '.join(report['orgs'])}")
    print(f"  Target package: {report['malicious_package']}  "
          f"flagged versions: {', '.join(report['malicious_versions'])}")

    print(f"\n  {'─' * W}")
    print(f"  {'SUMMARY':^{W}}")
    print(f"  {'─' * W}")
    print(f"  {'Repos scanned (axios found in package.json)':<50}: {s['total_repos_scanned']}")
    print(f"  {'Repos pinning MALICIOUS axios version':<50}: {s['repos_with_malicious_axios_count']}")
    print(f"  {'Workflow runs with NO cache action':<50}: {s['workflow_runs_no_cache_count']}")
    print(f"  {'Runs w/ malicious axios confirmed in job logs':<50}: {s.get('workflow_runs_axios_found_in_logs', 0)}")
    print(f"  {'Workflow runs in repos w/ malicious axios':<50}: {s['workflow_runs_in_malicious_repos']}")
    print(f"  {'─' * W}")

    # ── Section 1: Malicious repos ──────────────────────────────────────────
    if report["repos_with_malicious_axios"]:
        print(f"\n  ⚠️  REPOSITORIES WITH MALICIOUS {report['malicious_package'].upper()} ({len(report['repos_with_malicious_axios'])})")
        for e in report["repos_with_malicious_axios"]:
            print(f"\n    Repository  : {e['repo']}")
            print(f"    File        : {e['pkg_path']}")
            print(f"    Version spec: {e['axios_version_spec']}")
            print(f"    Malicious   : {'YES ⚠️' if e['malicious'] else 'no'}")
    else:
        print(f"\n  ✅  No repositories found with malicious axios version.")

    # ── Section 2: axios confirmed in job logs (highest severity) ────────────
    if report.get("workflow_runs_axios_in_logs"):
        print(f"\n\n  🚨 RUNS WITH MALICIOUS AXIOS CONFIRMED IN JOB LOGS "
              f"({len(report['workflow_runs_axios_in_logs'])})")
        for i, r in enumerate(report["workflow_runs_axios_in_logs"], 1):
            _print_run_card(r, f"[{i}/{len(report['workflow_runs_axios_in_logs'])}] "
                               f"CONFIRMED IN LOGS")
    else:
        print(f"\n  ✅  Malicious axios NOT found in any job logs.")

    # ── Section 3: Runs without cache ────────────────────────────────────────
    if report["workflow_runs_no_cache"]:
        print(f"\n\n  🔴 WORKFLOW RUNS WITH NO CACHE ACTION ({len(report['workflow_runs_no_cache'])})")
        for i, r in enumerate(report["workflow_runs_no_cache"], 1):
            _print_run_card(r, f"[{i}/{len(report['workflow_runs_no_cache'])}] NO-CACHE RUN")
    else:
        print(f"\n  ✅  All workflow runs in the window used a cache action.")

    # ── Section 4: Runs in malicious repos ───────────────────────────────────
    if report["workflow_runs_malicious_axios_repo"]:
        print(f"\n\n  ⚠️  WORKFLOW RUNS IN REPOS WITH MALICIOUS AXIOS "
              f"({len(report['workflow_runs_malicious_axios_repo'])})")
        for i, r in enumerate(report["workflow_runs_malicious_axios_repo"], 1):
            _print_run_card(r, f"[{i}/{len(report['workflow_runs_malicious_axios_repo'])}] "
                               f"MALICIOUS-AXIOS REPO RUN")
    else:
        print(f"\n  ✅  No workflow runs found in repos with malicious axios.")

    print("\n" + "═" * (W + 2) + "\n")


# ---------------------------------------------------------------------------
# Detail JSON writer
# ---------------------------------------------------------------------------

def write_detail_json(report: dict, path: str):
    """
    Write the full detail JSON — every repo scanned and every run checked,
    including those with no findings.  Logs are not embedded (too large);
    only the matched lines are stored.
    """
    detail = {
        "generated_at":    datetime.now(SGT).isoformat(),
        "incident":        report.get("incident", ""),
        "audit_window":    report["audit_window"],
        "orgs":            report["orgs"],
        "malicious_package":  report["malicious_package"],
        "malicious_versions": report["malicious_versions"],
        # ── All repos where axios appeared in package.json
        "all_repos_scanned": report.get("all_repos_scanned", []),
        # ── All workflow runs checked inside the time window
        "all_runs_checked":  report.get("all_runs_checked", []),
        # ── Flagged subsets (for quick triage)
        "flagged": {
            "repos_with_malicious_axios":        report["repos_with_malicious_axios"],
            "workflow_runs_no_cache":             report["workflow_runs_no_cache"],
            "workflow_runs_axios_in_logs":        report["workflow_runs_axios_in_logs"],
            "workflow_runs_malicious_axios_repo": report["workflow_runs_malicious_axios_repo"],
        },
        "summary": report["summary"],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(detail, fh, indent=2, default=str)
    log.info("Detail JSON written to: %s", path)


# ---------------------------------------------------------------------------
# PDF report generator
# ---------------------------------------------------------------------------

def generate_pdf_report(report: dict, path: str):
    """Generate a security-operations style PDF summary report."""
    try:
        from fpdf import FPDF
    except ImportError:
        log.warning("fpdf2 not installed — PDF skipped.  Run: pip install fpdf2")
        return

    s        = report["summary"]
    aw       = report["audit_window"]
    mal      = report.get("malicious_versions", sorted(MALICIOUS_VERSIONS))
    incident = report.get("incident", "")

    has_log_evidence  = s.get("workflow_runs_axios_found_in_logs", 0) > 0
    has_malicious_pkg = s.get("repos_with_malicious_axios_count", 0) > 0
    no_cache_count    = s.get("workflow_runs_no_cache_count", 0)

    if has_log_evidence:
        risk_label  = "HIGH"
        risk_rgb    = (192, 0, 0)
        conclusion  = (
            "Malicious axios was confirmed in workflow job logs. "
            "Immediate containment and forensic investigation required."
        )
    elif has_malicious_pkg:
        risk_label  = "MEDIUM"
        risk_rgb    = (200, 100, 0)
        conclusion  = (
            "A malicious axios version was found in package.json. "
            "No confirmed installation detected in logs. "
            "Dependency remediation required."
        )
    else:
        risk_label  = "LOW -- NO THREAT DETECTED"
        risk_rgb    = (0, 128, 0)
        conclusion  = (
            "No malicious axios version was found in any package.json or "
            "workflow job log within the monitored organization and time window. "
            "No action required."
        )

    # ── colour palette ──────────────────────────────────────────────────────
    C_DARK_BLUE = (31,  73, 125)
    C_MED_BLUE  = (68, 114, 196)
    C_LGRAY     = (242, 242, 242)
    C_WHITE     = (255, 255, 255)
    C_BLACK     = (0,   0,   0)
    C_DGRAY     = (80,  80,  80)
    C_GREEN     = (0,  128,   0)
    C_RED       = (192,  0,   0)

    # ── PDF subclass with footer ─────────────────────────────────────────────
    class _PDF(FPDF):
        def footer(self):
            self.set_y(-13)
            self.set_font("Helvetica", "I", 7.5)
            self.set_text_color(*C_DGRAY)
            self.set_draw_color(*C_MED_BLUE)
            self.set_line_width(0.3)
            self.line(15, self.get_y() - 1, self.w - 15, self.get_y() - 1)
            ref = f"{incident}  |  " if incident else ""
            self.cell(
                0, 6,
                f"{ref}Confidential - TLP:GREEN  |  "
                f"Generated {datetime.now(SGT).strftime('%Y-%m-%d %H:%M SGT')}  |  "
                f"Page {self.page_no()}/{{nb}}",
                align="C",
            )

    pdf = _PDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=22)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    # usable content width
    W = pdf.w - 30

    # ── helpers ─────────────────────────────────────────────────────────────
    def hline(y=None, rgb=C_MED_BLUE, thickness=0.4):
        y = y or pdf.get_y()
        pdf.set_draw_color(*rgb)
        pdf.set_line_width(thickness)
        pdf.line(15, y, 15 + W, y)
        pdf.ln(3)

    def section(title: str):
        pdf.ln(4)
        pdf.set_fill_color(*C_DARK_BLUE)
        pdf.set_text_color(*C_WHITE)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(W, 7.5, f"  {title}", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_text_color(*C_BLACK)
        pdf.ln(2)

    def body(text: str, size=9):
        pdf.set_font("Helvetica", "", size)
        pdf.set_text_color(*C_BLACK)
        pdf.multi_cell(W, 5, text)
        pdf.ln(1)

    def kv(label: str, value: str, lw=62):
        """Two-column key/value row that never overflows the right margin."""
        x0 = pdf.l_margin
        y0 = pdf.get_y()
        # label column (bold, fixed width, clipped)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_xy(x0, y0)
        pdf.cell(lw, 5.5, label)
        # value column (normal, wraps within remaining width)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_xy(x0 + lw, y0)
        pdf.multi_cell(W - lw, 5.5, f": {value}")
        # ensure y advances past the taller of the two columns
        pdf.set_y(max(pdf.get_y(), y0 + 5.5))

    def table_head(cols):
        """cols = list of (label, width)"""
        pdf.set_fill_color(*C_MED_BLUE)
        pdf.set_text_color(*C_WHITE)
        pdf.set_font("Helvetica", "B", 8.5)
        for label, w in cols:
            pdf.cell(w, 7, f"  {label}", fill=True)
        pdf.ln()
        pdf.set_text_color(*C_BLACK)

    def table_row(cols, row_idx=0):
        """cols = list of (value, width, status_flag)"""
        fill = (row_idx % 2 == 0)
        pdf.set_fill_color(*C_LGRAY)
        pdf.set_font("Helvetica", "", 8.5)
        for val, w, flag in cols:
            if flag == "ok":
                pdf.set_text_color(*C_GREEN)
            elif flag == "bad":
                pdf.set_text_color(*C_RED)
            else:
                pdf.set_text_color(*C_BLACK)
            pdf.cell(w, 6, f"  {val}", fill=fill)
        pdf.set_text_color(*C_BLACK)
        pdf.ln()

    # ════════════════════════════════════════════════════════════════════════
    # TITLE BANNER
    # ════════════════════════════════════════════════════════════════════════
    pdf.set_fill_color(*C_DARK_BLUE)
    pdf.rect(15, pdf.get_y(), W, 20, "F")
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*C_WHITE)
    pdf.cell(W, 20, "  SECURITY OPERATIONS REPORT", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*C_BLACK)
    pdf.ln(3)

    # META INFO
    metas = [
        ("Incident Reference", incident if incident else "N/A"),
        ("Classification",     "TLP:GREEN -- Internal Use"),
        ("Report Type",        "Threat Hunt -- Malicious npm Package (Supply Chain)"),
        ("Prepared by",        "Security Operations / Automated Scan"),
        ("Report Date",        datetime.now(SGT).strftime("%Y-%m-%d %H:%M SGT")),
    ]
    for label, val in metas:
        kv(label, val)
    pdf.ln(2)
    hline()

    # ════════════════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════════════════════════
    section("1. EXECUTIVE SUMMARY")
    body(
        f"A targeted security scan was conducted across the "
        f"{', '.join(report['orgs'])} GitHub organization to detect the presence of "
        f"known malicious axios npm package versions "
        f"({', '.join(mal)}) introduced via a confirmed npm registry supply chain "
        f"compromise. The scan covered all active repositories containing package.json "
        f"and all GitHub Actions workflow runs executed within the defined monitoring window."
    )
    # risk banner
    pdf.set_fill_color(*risk_rgb)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(W, 8, f"  RESULT:  Risk Level -- {risk_label}",
             new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_text_color(*C_BLACK)
    pdf.ln(2)

    # ════════════════════════════════════════════════════════════════════════
    # SCAN SCOPE
    # ════════════════════════════════════════════════════════════════════════
    section("2. SCAN SCOPE")
    cols_scope = [("Parameter", W * 0.38), ("Value", W * 0.62)]
    table_head(cols_scope)
    scope_rows = [
        ("Organization",        ", ".join(report["orgs"])),
        ("Target File",         "filename:package.json (all directories, non-archived)"),
        ("Malicious Package",   report.get("malicious_package", MALICIOUS_PACKAGE)),
        ("Flagged Versions",    ", ".join(mal)),
        ("Window Start (SGT)",  aw["start_sgt"]),
        ("Window End   (SGT)",  aw["end_sgt"]),
        ("Window Start (UTC)",  aw["start_utc"]),
        ("Window End   (UTC)",  aw["end_utc"]),
        ("Detection Method",
         "Static analysis (package.json) + Workflow job log scanning"),
    ]
    for i, (k, v) in enumerate(scope_rows):
        table_row([(k, W * 0.38, ""), (v, W * 0.62, "")], i)

    # ════════════════════════════════════════════════════════════════════════
    # FINDINGS
    # ════════════════════════════════════════════════════════════════════════
    section("3. FINDINGS")

    # 3a — Static
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(W, 6, "  3a.  Static Package Dependency Analysis",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    c1, c2, c3 = W * 0.50, W * 0.10, W * 0.40
    table_head([("Check", c1), ("Count", c2), ("Status", c3)])
    static_rows = [
        ("Repositories scanned for axios in package.json",
         str(s["total_repos_scanned"]), "Scanned", ""),
    ]
    for v in mal:
        cnt = s.get("repos_with_malicious_axios_count", 0)
        static_rows.append((
            f"Repositories pinning axios@{v}",
            str(cnt),
            "NOT FOUND" if cnt == 0 else f"FOUND ({cnt})",
            "ok" if cnt == 0 else "bad",
        ))
    for i, row in enumerate(static_rows):
        table_row([(row[0], c1, ""), (row[1], c2, ""),
                   (row[2], c3, row[3] if len(row) > 3 else "")], i)
    pdf.ln(3)

    # 3b — Workflow
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(W, 6, "  3b.  GitHub Actions Workflow Run Analysis",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    table_head([("Check", c1), ("Count", c2), ("Status", c3)])
    wf_data = [
        ("Workflow runs scanned in monitoring window",
         str(len(report.get("all_runs_checked", []))),
         "Scanned", ""),
        ("Runs with malicious axios confirmed in job logs",
         str(s.get("workflow_runs_axios_found_in_logs", 0)),
         "NOT DETECTED" if not has_log_evidence else
         f"DETECTED ({s['workflow_runs_axios_found_in_logs']})",
         "ok" if not has_log_evidence else "bad"),
        ("Runs with no actions/cache step (no cache hit)",
         str(no_cache_count),
         "NONE" if no_cache_count == 0 else f"FLAGGED ({no_cache_count})",
         "ok" if no_cache_count == 0 else "bad"),
    ]
    for i, row in enumerate(wf_data):
        table_row([(row[0], c1, ""), (row[1], c2, ""), (row[2], c3, row[3])], i)

    # ════════════════════════════════════════════════════════════════════════
    # THREAT INDICATORS
    # ════════════════════════════════════════════════════════════════════════
    section("4. THREAT INDICATORS CHECKED")
    ci, ct, cs = W * 0.40, W * 0.28, W * 0.32
    table_head([("Indicator (IOC)", ci), ("Type", ct), ("Status", cs)])
    ioc_rows = []
    for v in mal:
        cnt = s.get("repos_with_malicious_axios_count", 0)
        ioc_rows.append((
            f"axios@{v} in package.json",
            "Static dependency pin",
            "Not present" if cnt == 0 else "PRESENT",
            "ok" if cnt == 0 else "bad",
        ))
    for v in mal:
        cnt = s.get("workflow_runs_axios_found_in_logs", 0)
        ioc_rows.append((
            f"axios@{v} in npm install output",
            "Job log evidence",
            "Not detected" if cnt == 0 else "DETECTED",
            "ok" if cnt == 0 else "bad",
        ))
    ioc_rows.append((
        "Workflow runs without cache action",
        "Exposure indicator",
        "Not detected" if no_cache_count == 0 else f"{no_cache_count} run(s) flagged",
        "ok" if no_cache_count == 0 else "bad",
    ))
    for i, row in enumerate(ioc_rows):
        table_row([(row[0], ci, ""), (row[1], ct, ""), (row[2], cs, row[3])], i)

    # ════════════════════════════════════════════════════════════════════════
    # FLAGGED REPOS (only if there are any)
    # ════════════════════════════════════════════════════════════════════════
    if report.get("repos_with_malicious_axios"):
        section("5. FLAGGED REPOSITORIES")
        fr, fp, fv = W * 0.38, W * 0.30, W * 0.32
        table_head([("Repository", fr), ("File", fp), ("Version Spec", fv)])
        for i, e in enumerate(report["repos_with_malicious_axios"]):
            table_row([
                (e["repo"],              fr, "bad"),
                (e["pkg_path"],          fp, ""),
                (e["axios_version_spec"], fv, "bad"),
            ], i)
        pdf.ln(2)

    # ════════════════════════════════════════════════════════════════════════
    # CONCLUSION
    # ════════════════════════════════════════════════════════════════════════
    section("6. CONCLUSION & RISK ASSESSMENT")
    pdf.set_fill_color(*risk_rgb)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(W, 8, f"  Risk Level: {risk_label}",
             new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_text_color(*C_BLACK)
    pdf.ln(1)
    body(conclusion)

    # ════════════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ════════════════════════════════════════════════════════════════════════
    section("7. RECOMMENDATIONS")
    pkg = report.get("malicious_package", MALICIOUS_PACKAGE)
    vers = ", ".join(report.get("malicious_versions", sorted(MALICIOUS_VERSIONS)))
    recs = [
        f"Re-run this scan daily during the active incident window until the advisory for {pkg} is closed.",
        (
            f"Pin {pkg} to a verified safe version in all package.json files and commit the "
            "lockfile (package-lock.json or yarn.lock) to prevent unintentional resolution "
            f"to malicious versions ({vers})."
        ),
        (
            "Enable Dependabot or equivalent SCA tooling on all repositories to receive "
            "automated alerts on future malicious version publications."
        ),
        (
            "Retain workflow run logs beyond the default 90-day window for audit continuity "
            "during active incidents."
        ),
        (
            f"Consider adding an `npm audit --audit-level=critical` step to all CI workflows "
            f"to fail builds on known critical vulnerabilities in {pkg}."
        ),
    ]
    for i, rec in enumerate(recs, 1):
        y0 = pdf.get_y()
        num_w = 14
        # number bullet (bold)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_xy(pdf.l_margin, y0)
        pdf.cell(num_w, 5.5, f"{i}.")
        # recommendation text — wrapped within (W - num_w)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_xy(pdf.l_margin + num_w, y0)
        pdf.multi_cell(W - num_w, 5.5, rec)
        pdf.ln(1)
    pdf.ln(3)

    hline()
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.set_text_color(*C_DGRAY)
    ref_note = f"{incident} automated audit tool" if incident else "automated audit tool"
    pdf.multi_cell(
        W, 5,
        f"This report was generated by the GitHub Actions Axios Supply Chain {ref_note}. "
        "Full scan artifacts and raw JSON detail report are retained in the incident workspace.",
    )

    pdf.output(path)
    log.info("PDF report written to: %s", path)


def _parse_hhmm(value: str) -> tuple[int, int]:
    """Parse 'HH:MM' string into (hour, minute). Exits on bad format."""
    try:
        h, m = value.strip().split(":")
        return (int(h), int(m))
    except (ValueError, AttributeError):
        sys.exit(f"ERROR: Invalid time format '{value}'. Use HH:MM (e.g. 08:00).")


def main():
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # ── Apply dynamic runtime overrides to module-level constants ────────────
    global MALICIOUS_PACKAGE, MALICIOUS_VERSIONS, SGT_WINDOW_START, SGT_WINDOW_END
    global _AXIOS_LOG_PATTERNS

    MALICIOUS_PACKAGE  = args.package.strip()
    MALICIOUS_VERSIONS = {v.strip() for v in args.versions.split(",") if v.strip()}
    if not MALICIOUS_VERSIONS:
        sys.exit("ERROR: --versions must contain at least one version string.")

    SGT_WINDOW_START = _parse_hhmm(args.window_start)
    SGT_WINDOW_END   = _parse_hhmm(args.window_end)
    if SGT_WINDOW_START >= SGT_WINDOW_END:
        sys.exit(
            f"ERROR: --window-start ({args.window_start}) must be "
            f"earlier than --window-end ({args.window_end})."
        )

    # Rebuild log-scan patterns with the (possibly updated) versions
    _AXIOS_LOG_PATTERNS = _build_log_patterns()

    if not args.token:
        sys.exit(
            "ERROR: No GitHub token provided.\n"
            "Set GITHUB_TOKEN env var or pass --token <PAT>.\n"
            "The token needs: read:org, repo (read), actions (read)"
        )

    # Validate output paths — prevent path traversal
    out_summary = safe_output_path(args.output,      "audit_report.json")
    out_detail  = safe_output_path(args.detail_json, "audit_report_detail.json")
    out_pdf     = safe_output_path(args.pdf,         "audit_report_summary.pdf")

    orgs = [o.strip() for o in args.orgs.split(",") if o.strip()]
    if not orgs:
        sys.exit("ERROR: --orgs must contain at least one organisation name.")

    gh = GitHubClient(args.token)

    log.info("Starting audit  orgs=%s  date=%s  incident=%s",
             orgs, args.date or "today (SGT)", args.incident or "(none)")

    report = audit(orgs, args.date, gh, incident=args.incident)
    print_summary(report)

    # ── 1. Summary JSON (flagged items only)
    with open(out_summary, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    log.info("Summary JSON written to  : %s", out_summary)

    # ── 2. Detail JSON (every repo + every run)
    write_detail_json(report, out_detail)

    # ── 3. PDF summary report
    generate_pdf_report(report, out_pdf)
    log.info("Output files:")
    log.info("  Summary JSON : %s", out_summary)
    log.info("  Detail JSON  : %s", out_detail)
    log.info("  PDF report   : %s", out_pdf)


if __name__ == "__main__":
    main()
