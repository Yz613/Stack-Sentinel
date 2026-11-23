# StackSentinel

A simple, privacy-first GitHub vulnerability scanner built with Next.js + [vinext](https://vinext.dev/) on Cloudflare Workers.

Connect your GitHub account, scan your repositories against [OSV.dev](https://osv.dev) and [Helix Threat Watch](https://helix.ml/threat-watch?range=2026&chart=line), and copy ready-to-use **Agent Fix Prompts** for any affected repository.

**Live app:** [https://stack-sentinel.yehudazahler.workers.dev](https://stack-sentinel.yehudazahler.workers.dev)

---

## Quick Start

1. Open [https://stack-sentinel.yehudazahler.workers.dev](https://stack-sentinel.yehudazahler.workers.dev).
2. Create a GitHub Personal Access Token ([create one here](https://github.com/settings/tokens/new?scopes=repo&description=StackSentinel)):
   - Use the `repo` scope to include private repositories, or `public_repo` for public repositories only.
3. Paste your token into **Connect Your GitHub** and click **Connect & Scan My Repos**.

## Privacy & Security

- **Browser-only storage:** Your GitHub token, scan results, and dismissed issues are stored strictly in your own browser (`localStorage`).
- **Stateless scanning:** `POST /api/scan` scans your repositories in memory over HTTPS (`cache-control: private, no-store`) and never saves your token, repository names, or findings to a server database.
- **One-click disconnect:** Click **Disconnect** in the top bar at any time to clear your token and cached scan data from your browser.

## What You Get

- **One card per affected repository:** Open vulnerabilities are grouped by repo and sorted by severity (`CRITICAL` → `LOW`), showing the affected package, installed version, fixed version, manifest path, and advisory details.
- **Agent Fix Prompts:**
  - Single issue: click **Copy Fix Prompt** for a self-contained prompt with repo, branch, file path, package upgrade, and verification steps.
  - Multiple issues in one repo: click **Copy Master Prompt (N)** to bundle all open vulnerabilities in that repo into one numbered prompt for your coding agent.
- **On-demand rescanning:** Click **Scan Now** anytime to re-scan your repositories and check the latest Helix Threat Watch advisories.

## Supported Manifests & Ecosystems

StackSentinel inspects common dependency manifests and lockfiles across your repositories, including:
- **Node.js / npm:** `package.json`, `package-lock.json`
- **Python / PyPI:** `requirements.txt`, `pyproject.toml`
- **PHP / Packagist:** `composer.json`, `composer.lock`
- **Go:** `go.mod`
- **Containers / Runtimes:** `Dockerfile`, `.nvmrc`, `.node-version`, `.php-version`

---

## Self-Hosting / Local Development

```bash
npm install
npm run dev
```

To build and deploy your own Cloudflare Workers instance:

```bash
npm run build
npx wrangler deploy --config dist/server/wrangler.json
```

> **Note:** `wrangler.jsonc` also includes a D1 database binding (`stack-sentinel-db`) and an optional daily cron trigger (`0 14 * * *`) if you want to self-host a private single-tenant instance with server-side `GITHUB_TOKEN` and `APP_ACCESS_KEY` secrets.
