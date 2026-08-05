import React from "react";
import SeverityBar from "./SeverityBar";

export default function ScanLanes({byVersionAndSource}) {
  const rows = [...byVersionAndSource].sort((a, b) => {
    if (a.ballerina_version !== b.ballerina_version) {
      return b.ballerina_version.localeCompare(a.ballerina_version);
    }
    return a.source.localeCompare(b.source);
  });

  return (
    <section className="lanes-section">
      <h2>Scan lanes</h2>
      <div className="lanes-grid">
        {rows.map((s) => (
          <div key={`${s.ballerina_version}|${s.source}`} className={`lane ${s.ok ? "" : "lane-failed"}`}>
            <div className="lane-head">
              <span className="lane-version">{s.ballerina_version}</span>
              <span className="lane-source">{s.source}</span>
              <span className={`lane-status ${s.ok ? "lane-status-ok" : "lane-status-fail"}`}>
                {s.ok ? "● ok" : "● failed"}
              </span>
            </div>
            {s.ok ? (
              <SeverityBar counts={s.counts} />
            ) : (
              <p className="lane-error">{s.statusError || "unknown error"}</p>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
