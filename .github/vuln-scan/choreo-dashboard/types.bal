// Types mirroring combined.json, produced by the pipeline in
// Thevakumar-Luheerathan/ballerina-distribution/.github/vuln-scan/scripts/combine.py.
// Keep this in sync with that script's output shape - it is the single contract between
// Track A (the scan pipeline) and Track B (this dashboard).

public type IssueRef record {|
    int? number;
    string? url;
    string state; // "open" | "closed"
|};

public type Finding record {|
    string ballerina_version;
    string 'source; // "distribution" | "central" - NEVER merge across these when aggregating
    string? package_org;
    string package_name; // always populated: "ballerina-lang" for distribution, real name for central
    string? package_version;
    // Raw underlying dependency coordinate trivy reports (e.g. "io.netty:netty-codec"),
    // independent of which Ballerina package wraps it. Version-independent, so it's the only
    // reliable way to check "is this library used by anything on Central at all" - needed by
    // findPendingDistributionFixes to avoid falsely claiming a lang-only/tooling dependency
    // (e.g. commons-beanutils) is "already fixed on Central" when it was never published there.
    string library_name;
    string jar;
    string cve;
    string severity; // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    string installed_version;
    string fixed_version; // "" means no upstream fix exists yet
    // Other jar targets within the SAME package/distribution scan that reported the identical
    // CVE, collapsed into this one finding by combine.py's within-source dedup. Defaults to []
    // so a producer that omits the key (rather than sending an empty array) doesn't break
    // parsing - belt-and-suspenders, since combine.py always sets it today.
    string[] also_seen_in_jars = [];
    // Defaults to nil, not just nullable - a finding whose repo never resolved never gets this
    // key touched by issue_sync.py at all (verified: this broke parsing of every such finding
    // on this pipeline's first real end-to-end run against a live-generated report).
    IssueRef? issue = ();
|};

public type ScanStatus record {|
    string ballerina_version;
    string 'source;
    boolean ok;
    string? 'error;
|};

public type CombinedReport record {|
    string generated_at;
    // Optional with a default (not just nullable) - combine.py's output is the only producer
    // of this field, and a future version of it omitting the key entirely (as happened once
    // already - see git history) must not break parsing for everything else in the report.
    string? pipeline_run_url = ();
    string[] versions;
    ScanStatus[] scan_status;
    Finding[] findings;
|};

// --- Derived view models, aggregated in aggregate.bal and rendered by the React dashboard ---
//
// Package summaries use a three-level hierarchy: package -> version -> CVE. A package is one
// row/issue (identity = package_org + package_name, e.g. "ballerinax"/"redis", or package_name
// "ballerina-lang" alone). Each distinct version the package appears at gets its own VersionGroup
// - two versions of the same package can have genuinely different CVE sets (different build
// artifacts), so a version's findings must never be merged into a shared package-level list.

public type SeverityCounts record {|
    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
    int unknown = 0;
|};

public type VersionSourceSummary record {|
    string ballerina_version;
    string 'source;
    SeverityCounts counts;
    boolean ok;
    string? statusError;
|};

public type VersionGroup record {|
    string label; // e.g. "2.16.6 (2201.12.x, 2201.13.x)" for a central package, or "2201.12.x" for ballerina-lang
    string[] ballerina_versions;
    string? package_version; // null for ballerina-lang
    SeverityCounts counts;
    Finding[] findings; // ONLY the findings belonging to THIS version - never merged across versions
|};

public type PackageSummary record {|
    string? package_org;
    string package_name;
    string 'source;
    IssueRef? issue;
    SeverityCounts counts; // aggregate across all of this package's versions
    VersionGroup[] versions;
|};
