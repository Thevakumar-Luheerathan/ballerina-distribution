#!/usr/bin/env python3
"""
Combine per-version-line, per-source trivy JSON reports into one combined.json matching the
pipeline's contract (see the repo's vuln-scan plan for the full schema).

Inputs, per configured version line:
  --distribution-report <line>=<path>   a single trivy JSON report from scanning the built
                                         distribution (source "distribution"). Repeatable.
  --central-dir <line>=<path>           a directory produced by bala_scan.py: manifest.json +
                                         one trivy JSON report per package (source "central").
                                         Repeatable.
  --distribution-status <line>=ok|<error message>   whether the distribution build/scan for
                                         that line succeeded. Repeatable; if omitted for a line
                                         that has a --distribution-report, assumed ok.

Output: combined.json with top-level generated_at/versions/scan_status/findings, per the
pipeline contract. Findings are deduped WITHIN a source (a single package or the distribution
build re-reporting the same CVE against multiple shaded/fat jars collapses to one finding with
a note of how many jar targets it appeared in) and NEVER across sources - the whole point of
keeping "distribution" and "central" separate is to preserve the "already fixed on Central,
still pending in the distribution" signal, which a cross-source merge would destroy.
"""
import argparse
import json
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DISTRIBUTION_REPO = "ballerina-platform/ballerina-lang"


def load_exceptions():
    with open(os.path.join(SCRIPT_DIR, "repo_exceptions.json")) as f:
        return json.load(f)["exceptions"]


_repo_exists_cache = {}


def repo_exists(full_name):
    """Verify a guessed repo actually exists (and get gh to follow any rename redirect)."""
    if full_name in _repo_exists_cache:
        return _repo_exists_cache[full_name]
    proc = subprocess.run(
        ["gh", "api", f"repos/{full_name}", "--jq", ".full_name"],
        capture_output=True, text=True, timeout=20,
    )
    result = proc.stdout.strip() if proc.returncode == 0 else None
    _repo_exists_cache[full_name] = result
    return result


def resolve_repo(org, name, exceptions, unresolved):
    """
    Resolution order:
      1. explicit exception table (compiled from verified naming-convention mismatches)
      2. module-<org>-<name> convention, verified to actually exist via the GitHub API
         (this also transparently follows GitHub's rename redirects, e.g. for repos whose
         own Ballerina.toml has a stale `repository` field - we never trust that field
         directly, since it's self-reported and was found stale in 2 of 63 sampled repos)
    If neither resolves, the package is recorded in `unresolved` and the finding gets
    repo=None - it still appears in combined.json (never silently dropped) but can't be
    issue-synced until someone extends the exception table.
    """
    key = f"{org}/{name}"
    if key in exceptions:
        guess = exceptions[key]
        full = f"ballerina-platform/{guess}"
        resolved = repo_exists(full)
        if resolved:
            return resolved
    guess = f"module-{org}-{name}" if org != "ballerina" else f"module-ballerina-{name}"
    full = f"ballerina-platform/{guess}"
    resolved = repo_exists(full)
    if resolved:
        return resolved

    unresolved.setdefault(key, 0)
    unresolved[key] += 1
    return None


def parse_trivy_report(path):
    """
    Yields (jar_path, cve, severity, pkg_name, installed_version, fixed_version).

    Verified against real trivy 0.64.1 `rootfs` JSON output: when a rootfs scan finds multiple
    jars, `Results[].Target` is an aggregate label like "Java" or "Node.js" - NOT a jar path.
    The actual per-finding jar lives on each vulnerability entry as `PkgPath`
    (e.g. "platform/java21/netty-codec-4.1.115.Final.jar"). We fall back to `Target` only if
    `PkgPath` is absent, since some rootfs scan modes (observed in ballerina-lang's own
    distribution scan) DO report one Target per jar directly.
    """
    with open(path) as f:
        data = json.load(f)
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            jar_path = vuln.get("PkgPath") or target
            yield (
                jar_path,
                vuln.get("VulnerabilityID"),
                vuln.get("Severity"),
                vuln.get("PkgName"),
                vuln.get("InstalledVersion"),
                vuln.get("FixedVersion", ""),
            )


def dedupe_within_source(raw_findings, dedupe_key_fn):
    """
    raw_findings: list of dicts already carrying all schema fields except dedup bookkeeping.
    Collapses entries whose dedupe_key_fn(...) matches, keeping the first jar seen and
    recording how many distinct jar targets reported the same CVE.
    """
    by_key = {}
    order = []
    for finding in raw_findings:
        key = dedupe_key_fn(finding)
        if key not in by_key:
            by_key[key] = finding
            finding["_also_seen_in_jars"] = []
            order.append(key)
        else:
            existing = by_key[key]
            if finding["jar"] != existing["jar"]:
                existing["_also_seen_in_jars"].append(finding["jar"])
    return [by_key[k] for k in order]


def process_distribution_report(line, report_path, findings_out):
    raw = []
    for target, cve, severity, pkg_name, installed, fixed in parse_trivy_report(report_path):
        jar = os.path.basename(target)
        raw.append({
            "ballerina_version": line,
            "source": "distribution",
            "package_org": None,
            "package_name": pkg_name,
            "package_version": None,
            "repo": DISTRIBUTION_REPO,
            "jar": jar,
            "cve": cve,
            "severity": severity,
            "installed_version": installed,
            "fixed_version": fixed,
        })
    deduped = dedupe_within_source(raw, lambda f: (f["cve"], f["package_name"], f["installed_version"]))
    findings_out.extend(deduped)


def process_central_dir(line, central_dir, findings_out, exceptions, unresolved):
    manifest_path = os.path.join(central_dir, "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)

    for pkg in manifest.get("scanned", []):
        report_path = os.path.join(central_dir, pkg["report"])
        if not os.path.exists(report_path):
            continue
        repo = resolve_repo(pkg["org"], pkg["name"], exceptions, unresolved)
        raw = []
        for target, cve, severity, pkg_name, installed, fixed in parse_trivy_report(report_path):
            jar = os.path.basename(target)
            raw.append({
                "ballerina_version": line,
                "source": "central",
                "package_org": pkg["org"],
                "package_name": pkg["name"],
                "package_version": pkg["version"],
                "repo": repo,
                "jar": jar,
                "cve": cve,
                "severity": severity,
                "installed_version": installed,
                "fixed_version": fixed,
            })
        deduped = dedupe_within_source(raw, lambda f: f["cve"])
        findings_out.extend(deduped)


def parse_kv_args(items):
    """'2201.12.x=/path/to/file' -> {'2201.12.x': '/path/to/file'}"""
    out = {}
    for item in items or []:
        line, _, value = item.partition("=")
        out[line] = value
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--distribution-report", action="append", default=[])
    ap.add_argument("--central-dir", action="append", default=[])
    ap.add_argument("--distribution-status", action="append", default=[])
    ap.add_argument("--central-status", action="append", default=[])
    ap.add_argument("--out", required=True)
    ap.add_argument("--unresolved-out", default=None)
    args = ap.parse_args()

    dist_reports = parse_kv_args(args.distribution_report)
    central_dirs = parse_kv_args(args.central_dir)
    dist_status = parse_kv_args(args.distribution_status)
    central_status = parse_kv_args(args.central_status)

    exceptions = load_exceptions()
    unresolved = {}
    findings = []
    scan_status = []
    versions = sorted(set(list(dist_reports) + list(central_dirs)))

    for line in versions:
        if line in dist_reports:
            try:
                process_distribution_report(line, dist_reports[line], findings)
                ok = dist_status.get(line, "ok") == "ok"
                scan_status.append({
                    "ballerina_version": line, "source": "distribution",
                    "ok": ok, "error": None if ok else dist_status.get(line),
                })
            except Exception as e:  # noqa: BLE001
                scan_status.append({
                    "ballerina_version": line, "source": "distribution",
                    "ok": False, "error": str(e),
                })
        else:
            scan_status.append({
                "ballerina_version": line, "source": "distribution",
                "ok": False, "error": "no report produced",
            })

        if line in central_dirs:
            try:
                process_central_dir(line, central_dirs[line], findings, exceptions, unresolved)
                ok = central_status.get(line, "ok") == "ok"
                scan_status.append({
                    "ballerina_version": line, "source": "central",
                    "ok": ok, "error": None if ok else central_status.get(line),
                })
            except Exception as e:  # noqa: BLE001
                scan_status.append({
                    "ballerina_version": line, "source": "central",
                    "ok": False, "error": str(e),
                })
        else:
            scan_status.append({
                "ballerina_version": line, "source": "central",
                "ok": False, "error": "no report produced",
            })

    combined = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "versions": versions,
        "scan_status": scan_status,
        "findings": findings,
    }

    with open(args.out, "w") as f:
        json.dump(combined, f, indent=2)

    print(
        f"Wrote {len(findings)} findings across {len(versions)} version line(s) to {args.out}",
        file=sys.stderr,
    )
    if unresolved:
        print(f"WARNING: {len(unresolved)} package(s) could not be resolved to a repo:", file=sys.stderr)
        for key, count in unresolved.items():
            print(f"  {key} ({count} finding(s))", file=sys.stderr)
    if args.unresolved_out:
        with open(args.unresolved_out, "w") as f:
            json.dump(unresolved, f, indent=2)


if __name__ == "__main__":
    main()
