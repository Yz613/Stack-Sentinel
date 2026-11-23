# StackSentinel

A multi-repository security dashboard and on-demand **Advisory Check** radar built with Next.js + [vinext](https://vinext.dev/) and deployed on **Cloudflare Workers + D1**.

## Features

- **Fleet Advisory Check (Two-Stage Engine)**
  - Paste a CVE/GHSA ID (e.g. `CVE-2025-29927`), an advisory URL, or a plain-English description (e.g. *"new PHP-CGI vulnerability"*).
  - **Stage 1 (Deterministic Filter):** Instantly evaluates every repository's languages, frameworks, manifests, lockfiles, and Docker base images to clear unaffected repos with explicit reasons.
  - **Stage 2 (Targeted Code & Reachability Triage):** Inspects candidate repositories for relevant security/config files (`middleware.ts`, `Dockerfile`, `wrangler.toml`, `composer.json`), flags unpinned production runtimes, and runs targeted GitHub Code Search when connected.
- **Unified Security Findings:** Consolidates dependency CVEs (queried via [OSV.dev](https://osv.dev)) and unpinned-runtime alerts across all repositories with severity/status filtering and persistent `Open` / `Acknowledged` / `Dismissed` triage.
- **Repository Inventory & SBOM Explorer:** Browse every repo's detected stack, runtime pins, key config files, and indexed packages in one view.
- **Cloudflare D1 Persistence:** Stores cached SBOM snapshots, triage statuses, scan runs, and advisory check history natively in Cloudflare D1 (auto-provisioned via `wrangler.jsonc`).

## Local Development (Workers runtime)

```bash
npm install
npm run dev
```

The app ships with a scanned snapshot of the connected GitHub account (repositories, manifests, and OSV advisories). Without a Worker `GITHUB_TOKEN`, **Sync Fleet** reloads that snapshot. With the token set, **Sync Fleet** rescans GitHub live. If neither the snapshot nor the token is available, the app falls back to 8 sample repositories.

## Deploying to Cloudflare Workers

```bash
npm run build
npx wrangler deploy --config dist/server/wrangler.json
```

### Worker Secrets

Set these in the Cloudflare Dashboard (**Workers & Pages → stack-sentinel → Settings → Variables and Secrets**) or with Wrangler:

```bash
npx wrangler secret put GITHUB_TOKEN
# Recommended before connecting private repositories:
npx wrangler secret put APP_ACCESS_KEY
```

Alternatively, place the Worker behind **Cloudflare Access (Zero Trust)** — StackSentinel automatically reads `Cf-Access-Authenticated-User-Email`.
