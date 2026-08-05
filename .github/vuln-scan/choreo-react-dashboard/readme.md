# Ballerina Vulnerability Scan Dashboard (React)

A React frontend for the proactive Ballerina vulnerability scan pipeline (Phase 1 - see
[wso2-enterprise/integration-engineering#2164](https://github.com/wso2-enterprise/integration-engineering/issues/2164)).
It renders the same views the pipeline used to serve as static HTML - summary by version and
source, "fixed on Central, pending in distribution", per-repo breakdown, and a filterable list
of every finding - by consuming the JSON API exposed by the separate `choreo-dashboard`
Ballerina service (`../choreo-dashboard`).

Built with [Vite](https://vitejs.dev/) rather than Create React App: same React code the
[wso2/choreo-samples `react-single-page-app`](https://github.com/wso2/choreo-samples/tree/main/react-single-page-app)
reference uses, but CRA's `react-scripts` toolchain is unmaintained and pulled in 28 known
vulnerabilities (14 high) at `npm install` time - Vite's equivalent toolchain has 2 (both
dev-server-only, not present in the production build). Choreo's React buildpack only needs
`npm run build` to produce a static output directory; it doesn't require CRA specifically.

## Deploy in Choreo

- Fork this repository (or point Choreo at your own copy).
- Create a **Web Application** component in Choreo, using:

| Setting | Value |
|---|---|
| Build Pack | React |
| Project Directory | `.github/vuln-scan/choreo-react-dashboard` |
| Build Command | `npm run build` |
| Build output directory | `dist` |
| Node Version | `20` |

- Set a **build-time** environment variable on the component:
  - `VITE_API_BASE_URL` - the deployed URL of the `choreo-dashboard` Service component (see
    `../choreo-dashboard/readme.md` if present, or its Choreo component's exposed URL).
    Vite only inlines `VITE_`-prefixed variables, and only at build time - this cannot be
    changed at runtime without rebuilding.
- On the `choreo-dashboard` Service component, set its `allowOrigins` configurable (in
  `Config.toml` or Choreo's environment variable equivalent) to this web app's actual deployed
  origin once known, narrowing it from the permissive `["*"]` default.

## Local development

```bash
npm install
cp .env.example .env.local   # then edit VITE_API_BASE_URL to point at a running
                              # choreo-dashboard instance (e.g. http://localhost:9091)
npm run dev                  # dev server with hot reload
npm run build                # production build -> dist/
```
