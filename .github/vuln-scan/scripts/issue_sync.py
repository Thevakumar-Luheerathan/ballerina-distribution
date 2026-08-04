#!/usr/bin/env python3
"""
Sync combined.json findings to GitHub issues, one issue per affected repo, in a tracking repo
(currently Thevakumar-Luheerathan/integration-engineering - the user's fork; migrating to the
upstream wso2-enterprise/integration-engineering later is a --tracking-repo + token swap only).

Design (confirmed with user this session):
  - One issue per repo, not per-CVE, not per-version. The issue body is a table of every
    current finding for that repo across all version lines and sources, REWRITTEN each run -
    not appended to. This is what gives free dedup, auto-close-on-fix, and history without a
    database: GitHub Issues themselves are the state store.
  - No assignee (confirmed with user - CODEOWNERS is unreliable for this: one individual
    appears on 67% of repos, so auto-assignment would spam them).
  - A repo whose finding count drops to zero gets its issue closed automatically, with a
    comment explaining why (rather than silently vanishing, so there's an audit trail).
  - The issue is found by a deterministic label ("trivy-scan") + title convention
    ("[trivy] <repo>"), NOT by reading a cached issue number from a previous combined.json -
    that field is a DERIVED output of this script, never an input to it. A stale cached link
    would rot silently if someone closed/renamed the issue by hand; re-deriving it from GitHub
    itself every run is what keeps this correct.

This script mutates combined.json IN PLACE, writing {"number", "url", "state"} onto every
finding that belongs to a resolved repo. Findings with repo=None (couldn't be mapped - see
combine.py's --unresolved-out) are left with issue=None; they still appear in combined.json so
the gap is visible on the dashboard, not silently dropped.

Requires: `gh` CLI authenticated with a token that has issue read/write on --tracking-repo.
"""
import argparse
import json
import subprocess
import sys
from collections import defaultdict

LABEL = "trivy-scan"


def gh(args, input_text=None):
    proc = subprocess.run(
        ["gh"] + args, capture_output=True, text=True, input=input_text, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def ensure_label_exists(tracking_repo):
    existing = gh(["label", "list", "--repo", tracking_repo, "--json", "name"])
    names = {item["name"] for item in json.loads(existing)}
    if LABEL not in names:
        gh([
            "label", "create", LABEL, "--repo", tracking_repo,
            "--color", "B60205", "--description", "Auto-filed by the Ballerina vulnerability scan pipeline",
        ])


def list_open_tracked_repos(tracking_repo):
    """
    Derive the set of repos with a currently-OPEN trivy-scan issue, straight from GitHub - no
    artifact plumbing needed across runs. Any repo in this set that has zero findings in the
    CURRENT run is a repo that just went clean and should have its issue closed.
    """
    result = gh([
        "issue", "list", "--repo", tracking_repo, "--label", LABEL, "--state", "open",
        "--json", "title", "--limit", "1000",
    ])
    repos = set()
    for item in json.loads(result):
        title = item["title"]
        if title.startswith("[trivy] "):
            repos.add(title[len("[trivy] "):])
    return repos


def find_existing_issue(tracking_repo, repo_name):
    title = f"[trivy] {repo_name}"
    result = gh([
        "issue", "list", "--repo", tracking_repo, "--label", LABEL,
        "--state", "all", "--search", f'"{title}" in:title',
        "--json", "number,title,state,url",
    ])
    for item in json.loads(result):
        if item["title"] == title:
            return item
    return None


def render_body(repo_name, findings):
    lines = [
        f"Automatically tracked vulnerabilities for `{repo_name}`, across all scanned "
        f"Ballerina version lines and sources. This issue's body is fully rewritten on every "
        f"pipeline run to reflect current findings - manual edits here will be overwritten. "
        f"To suppress a finding, use the repo's own `.trivyignore` (with a comment and, where "
        f"possible, an expiry) rather than editing this issue.",
        "",
        "| Version | Source | Package | Jar | CVE | Severity | Installed | Fixed |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in sorted(findings, key=lambda f: (f["ballerina_version"], f["source"], f["cve"] or "")):
        pkg = f"{f['package_org']}/{f['package_name']}@{f['package_version']}" if f["package_org"] else "-"
        also = f["_also_seen_in_jars"] if f.get("_also_seen_in_jars") else []
        jar = f["jar"] + (f" (+{len(also)} more)" if also else "")
        fixed = f["fixed_version"] or "_no fix available yet_"
        lines.append(
            f"| {f['ballerina_version']} | {f['source']} | {pkg} | {jar} | "
            f"{f['cve']} | {f['severity']} | {f['installed_version']} | {fixed} |"
        )
    return "\n".join(lines)


def sync_repo(tracking_repo, repo_name, findings, dry_run):
    existing = find_existing_issue(tracking_repo, repo_name)
    body = render_body(repo_name, findings)
    title = f"[trivy] {repo_name}"

    if existing is None:
        if dry_run:
            print(f"[dry-run] would CREATE issue for {repo_name} ({len(findings)} findings)", file=sys.stderr)
            return {"number": None, "url": None, "state": "open"}
        out = gh([
            "issue", "create", "--repo", tracking_repo, "--title", title,
            "--body", body, "--label", LABEL,
        ])
        # `gh issue create` prints the created issue's URL as its only stdout line.
        url = out.strip().splitlines()[-1]
        number = int(url.rstrip("/").rsplit("/", 1)[-1])
        return {"number": number, "url": url, "state": "open"}

    if existing["state"].lower() == "closed":
        # Findings reappeared on a repo whose issue we'd previously closed - reopen it rather
        # than leaving a stale "closed" issue that no longer reflects reality.
        if not dry_run:
            gh(["issue", "reopen", str(existing["number"]), "--repo", tracking_repo])
        existing["state"] = "OPEN"

    if not dry_run:
        gh([
            "issue", "edit", str(existing["number"]), "--repo", tracking_repo,
            "--body", body,
        ])
    return {"number": existing["number"], "url": existing["url"], "state": existing["state"].lower()}


def close_resolved_repo(tracking_repo, repo_name, dry_run):
    existing = find_existing_issue(tracking_repo, repo_name)
    if existing is None or existing["state"].lower() == "closed":
        return
    if dry_run:
        print(f"[dry-run] would CLOSE issue for {repo_name} (no findings remain)", file=sys.stderr)
        return
    gh([
        "issue", "comment", str(existing["number"]), "--repo", tracking_repo,
        "--body", "No open findings remain for this repo as of the latest scan. Closing.",
    ])
    gh(["issue", "close", str(existing["number"]), "--repo", tracking_repo])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--combined", required=True, help="combined.json to read AND update in place")
    ap.add_argument("--tracking-repo", default="Thevakumar-Luheerathan/integration-engineering")
    ap.add_argument("--previously-tracked-repos", default=None,
                     help="optional override: a JSON file listing repo names to check for "
                          "closing, instead of auto-deriving them from currently-open "
                          "trivy-scan issues in --tracking-repo. Mainly useful for testing; "
                          "normal runs should omit this and let it auto-derive.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    with open(args.combined) as f:
        combined = json.load(f)

    ensure_label_exists(args.tracking_repo)

    by_repo = defaultdict(list)
    for finding in combined["findings"]:
        if finding.get("repo"):
            by_repo[finding["repo"]].append(finding)

    for repo_name, findings in by_repo.items():
        issue = sync_repo(args.tracking_repo, repo_name, findings, args.dry_run)
        for f in findings:
            f["issue"] = issue
        print(f"{repo_name}: {len(findings)} finding(s) -> issue {issue.get('url') or '(dry-run)'}", file=sys.stderr)

    if args.previously_tracked_repos:
        with open(args.previously_tracked_repos) as f:
            previously = set(json.load(f))
    else:
        previously = list_open_tracked_repos(args.tracking_repo)

    newly_clean = previously - set(by_repo.keys())
    for repo_name in newly_clean:
        close_resolved_repo(args.tracking_repo, repo_name, args.dry_run)
        print(f"{repo_name}: 0 findings -> issue closed", file=sys.stderr)

    with open(args.combined, "w") as f:
        json.dump(combined, f, indent=2)


if __name__ == "__main__":
    main()
