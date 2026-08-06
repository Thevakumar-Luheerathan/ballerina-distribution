import React, {useCallback, useEffect, useState} from "react";
import "./App.css";
import {fetchSummary, triggerRefresh} from "./api";
import ScanLanes from "./components/ScanLanes";
import PackageTable from "./components/PackageTable";
import ThemeToggle from "./components/ThemeToggle";

function formatTimestamp(iso) {
  if (!iso) return "unknown";
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const summary = await fetchSummary();
      setData(summary);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await triggerRefresh();
      // The backend's refresh is itself async (it re-fetches from GitHub), so give it a
      // moment before re-pulling the summary rather than racing it.
      await new Promise((resolve) => setTimeout(resolve, 2000));
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-title">
          <h1>Vulnerability Scan</h1>
          <span className="topbar-sub">Ballerina dependency triage</span>
        </div>
        <div className="topbar-actions">
          <ThemeToggle />
          <button className="btn-refresh" onClick={handleRefresh} disabled={refreshing || loading}>
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </header>

      {loading && (
        <div className="state-panel">
          <div className="spinner" aria-hidden="true" />
          <p>Loading the latest scan…</p>
        </div>
      )}

      {!loading && error && (
        <div className="state-panel state-error">
          <p className="state-title">Couldn't load scan data</p>
          <p>{error}</p>
          <button className="btn-refresh" onClick={load}>Try again</button>
        </div>
      )}

      {!loading && !error && data && (
        <>
          <p className="meta-line">
            Generated {formatTimestamp(data.generatedAt)} &middot; fetched {formatTimestamp(data.fetchedAt)} &middot;{" "}
            <a href={data.runUrl} target="_blank" rel="noreferrer">view pipeline run</a>
          </p>

          {data.stale && (
            <div className="banner stale">
              <strong>This data is stale.</strong> The scan pipeline hasn't refreshed recently -
              it may have failed or not fired. Check the{" "}
              <a href={data.runUrl} target="_blank" rel="noreferrer">last known-good run</a>.
            </div>
          )}

          <ScanLanes byVersionAndSource={data.byVersionAndSource} />
          <PackageTable byPackage={data.byPackage} />
          <PackageTable byPackage={data.byPlugin} heading="Plugins" />
        </>
      )}
    </div>
  );
}

export default App;
