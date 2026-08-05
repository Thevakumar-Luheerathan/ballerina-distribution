// Talks to the Ballerina dashboard API (a separate Choreo Service component - see
// .github/vuln-scan/choreo-dashboard/main.bal's GET /api/summary). The base URL is a build-time
// env var: Vite only inlines variables prefixed VITE_, and it bakes them in at build time (not
// runtime) - so this must be set as a build-time environment variable in the Choreo console for
// the React "Web Application" component, not a runtime config file. There is no Choreo
// runtime-config-injection convention to fall back on here - the reference sample
// (wso2/choreo-samples/react-single-page-app) doesn't demonstrate one either (verified: it's a
// stock, backend-less scaffold with no API calls at all).
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

export async function fetchSummary() {
  if (!API_BASE_URL) {
    throw new Error(
      "VITE_API_BASE_URL is not set - this must point at the deployed choreo-dashboard " +
        "service's URL, configured as a build-time environment variable for this component."
    );
  }
  const response = await fetch(`${API_BASE_URL}/api/summary`);
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`API returned ${response.status}: ${body || response.statusText}`);
  }
  return response.json();
}

export async function triggerRefresh() {
  const response = await fetch(`${API_BASE_URL}/refresh`, {method: "POST"});
  if (!response.ok) {
    throw new Error(`Refresh request returned ${response.status}`);
  }
  return response.json();
}
