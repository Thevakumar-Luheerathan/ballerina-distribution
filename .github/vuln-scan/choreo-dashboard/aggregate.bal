// Pure aggregation logic over a CombinedReport - no I/O, so this is the easiest part of the
// service to unit-test directly (see tests/aggregate_test.bal).

function bumpSeverity(SeverityCounts counts, string severity) returns SeverityCounts {
    SeverityCounts updated = counts.clone();
    string s = severity.toUpperAscii();
    if s == "CRITICAL" {
        updated.critical += 1;
    } else if s == "HIGH" {
        updated.high += 1;
    } else if s == "MEDIUM" {
        updated.medium += 1;
    } else if s == "LOW" {
        updated.low += 1;
    } else {
        updated.unknown += 1;
    }
    return updated;
}

public function summarizeByVersionAndSource(CombinedReport report) returns VersionSourceSummary[] {
    map<VersionSourceSummary> byKey = {};

    // Seed every (version, source) pair from scan_status FIRST, so a source that scanned
    // clean (zero findings) still appears - the whole point of surfacing scan_status is that
    // "no findings" and "didn't run" must never look identical.
    foreach ScanStatus status in report.scan_status {
        string key = status.ballerina_version + "|" + status.'source;
        byKey[key] = {
            ballerina_version: status.ballerina_version,
            'source: status.'source,
            counts: {},
            ok: status.ok,
            statusError: status.'error
        };
    }

    foreach Finding f in report.findings {
        string key = f.ballerina_version + "|" + f.'source;
        VersionSourceSummary? existing = byKey[key];
        VersionSourceSummary current = existing ?: {
            ballerina_version: f.ballerina_version,
            'source: f.'source,
            counts: {},
            ok: true,
            statusError: ()
        };
        current.counts = bumpSeverity(current.counts, f.severity);
        byKey[key] = current;
    }

    VersionSourceSummary[] result = byKey.toArray();
    result = from var s in result
        order by s.ballerina_version descending, s.'source ascending
        select s;
    return result;
}

function packageKey(Finding f) returns string {
    return (f.package_org ?: "") + "|" + f.package_name;
}

// Groups a package's findings into VersionGroups per the package -> version -> CVE hierarchy.
// Each version's findings list belongs ONLY to that version - two versions of the same package
// can have genuinely different CVE sets (different build artifacts), so merging them would
// misattribute which CVE applies to which version. Mirrors issue_sync.py's version_groups().
function buildVersionGroups(string packageName, Finding[] findings) returns VersionGroup[] {
    map<Finding[]> byVersionKey = {};
    map<string[]> linesByPkgVersion = {};

    if packageName == "ballerina-lang" {
        foreach Finding f in findings {
            Finding[] existing = byVersionKey[f.ballerina_version] ?: [];
            existing.push(f);
            byVersionKey[f.ballerina_version] = existing;
        }
        VersionGroup[] groups = [];
        foreach string line in byVersionKey.keys() {
            Finding[] groupFindings = byVersionKey[line] ?: [];
            SeverityCounts counts = {};
            foreach Finding f in groupFindings {
                counts = bumpSeverity(counts, f.severity);
            }
            groups.push({
                label: line,
                ballerina_versions: [line],
                package_version: (),
                counts,
                findings: groupFindings
            });
        }
        return from var g in groups order by g.label ascending select g;
    }

    foreach Finding f in findings {
        string pkgVersion = f.package_version ?: "";
        Finding[] existing = byVersionKey[pkgVersion] ?: [];
        existing.push(f);
        byVersionKey[pkgVersion] = existing;

        string[] lines = linesByPkgVersion[pkgVersion] ?: [];
        if lines.indexOf(f.ballerina_version) is () {
            lines.push(f.ballerina_version);
        }
        linesByPkgVersion[pkgVersion] = lines;
    }

    VersionGroup[] groups = [];
    foreach string pkgVersion in byVersionKey.keys() {
        Finding[] groupFindings = byVersionKey[pkgVersion] ?: [];
        string[] lines = linesByPkgVersion[pkgVersion] ?: [];
        string[] sortedLines = from var l in lines order by l ascending select l;
        SeverityCounts counts = {};
        foreach Finding f in groupFindings {
            counts = bumpSeverity(counts, f.severity);
        }
        groups.push({
            label: string `${pkgVersion} (${string:'join(", ", ...sortedLines)})`,
            ballerina_versions: sortedLines,
            package_version: pkgVersion,
            counts,
            findings: groupFindings
        });
    }
    return from var g in groups order by g.label ascending select g;
}

public function summarizeByPackage(CombinedReport report) returns PackageSummary[] {
    map<Finding[]> byPackage = {};
    map<IssueRef?> issueByPackage = {};
    foreach Finding f in report.findings {
        string key = packageKey(f);
        Finding[] existing = byPackage[key] ?: [];
        existing.push(f);
        byPackage[key] = existing;
        if !issueByPackage.hasKey(key) {
            issueByPackage[key] = f.issue;
        }
    }

    PackageSummary[] result = [];
    foreach string key in byPackage.keys() {
        Finding[] findings = byPackage[key] ?: [];
        if findings.length() == 0 {
            continue;
        }
        Finding first = findings[0];
        VersionGroup[] versions = buildVersionGroups(first.package_name, findings);
        SeverityCounts packageCounts = {};
        foreach Finding f in findings {
            packageCounts = bumpSeverity(packageCounts, f.severity);
        }
        result.push({
            package_org: first.package_org,
            package_name: first.package_name,
            'source: first.'source,
            issue: issueByPackage[key] ?: (),
            counts: packageCounts,
            versions
        });
    }

    return from var p in result
        order by p.counts.critical descending, p.counts.high descending
        select p;
}

