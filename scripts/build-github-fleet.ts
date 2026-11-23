import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  mergeDependencies,
  parseComposerJson,
  parseComposerLock,
  parseDockerfile,
  parseGoMod,
  parsePackageJson,
  parsePackageLockJson,
  parsePyprojectToml,
  parseRequirementsTxt,
} from "../src/lib/manifests.ts";
import type { DependencyItem, RepoSnapshot, RuntimeSignal, VulnerabilityFinding } from "../src/lib/types.ts";

const PARTS_DIR = "/tmp/fleet-parts";
const META_PATH =
  "/home/ubuntu/.cursor/projects/agent-repos-tmp-6d1343778da2e05d/agent-tools/9dd265e3-16d6-483a-8970-dd83a8b07d04.txt";
const OUT_PATH = path.resolve("src/data/github-fleet.json");

const EXT_LANG: Record<string, string> = {
  ts: "TypeScript",
  tsx: "TypeScript",
  js: "JavaScript",
  jsx: "JavaScript",
  py: "Python",
  php: "PHP",
  go: "Go",
  kt: "Kotlin",
  swift: "Swift",
  java: "Java",
  rb: "Ruby",
  rs: "Rust",
};

interface PartFile {
  fullName: string;
  defaultBranch?: string;
  keyFiles?: string[];
  languageHints?: Record<string, number>;
  files?: Array<{ path: string; content: string }>;
  error?: string;
}

interface RepoMeta {
  full_name: string;
  html_url: string;
  description: string | null;
  private: boolean;
  default_branch: string;
  language: string | null;
  pushed_at: string | null;
}

async function queryOsv(
  repoFullName: string,
  dependencies: DependencyItem[],
): Promise<VulnerabilityFinding[]> {
  const queryable = dependencies
    .filter(
      (d) =>
        d.version &&
        d.version !== "unpinned" &&
        /^\d+\.\d+/.test(d.version) &&
        ["npm", "Packagist", "PyPI", "Go", "crates.io"].includes(d.ecosystem),
    )
    .slice(0, 80);
  if (queryable.length === 0) return [];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        queries: queryable.map((d) => ({
          package: { name: d.name, ecosystem: d.ecosystem },
          version: d.version,
        })),
      }),
      signal: controller.signal,
    });
    if (!res.ok) return [];
    const payload = (await res.json()) as {
      results?: Array<{ vulns?: Array<{ id: string }> }>;
    };
    const findings: VulnerabilityFinding[] = [];
    const seen = new Set<string>();
    for (let i = 0; i < queryable.length; i++) {
      const dep = queryable[i];
      for (const vuln of (payload.results?.[i]?.vulns ?? []).slice(0, 2)) {
        if (!vuln.id) continue;
        const key = `${repoFullName}:${vuln.id}:${dep.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `${repoFullName}::${vuln.id}::${dep.name}`.toLowerCase(),
          repoFullName,
          advisoryId: vuln.id,
          aliases: [],
          title: `Known vulnerability ${vuln.id} in ${dep.name}@${dep.version}`,
          summary: "",
          severity: "MEDIUM",
          category: "dependency",
          ecosystem: dep.ecosystem,
          packageName: dep.name,
          installedVersion: dep.version,
          fixedVersion: "",
          manifestPath: dep.manifestPath,
          referenceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`,
          status: "open",
          detectedAt: new Date().toISOString(),
        });
      }
    }

    const uniqueIds = [...new Set(findings.map((f) => f.advisoryId))].slice(0, 24);
    const details = new Map<string, { summary?: string; details?: string; aliases?: string[]; severity?: string }>();
    await Promise.all(
      uniqueIds.map(async (id) => {
        try {
          const detailRes = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
          if (!detailRes.ok) return;
          const body = (await detailRes.json()) as {
            summary?: string;
            details?: string;
            aliases?: string[];
            database_specific?: { severity?: string };
            severity?: Array<{ score?: string }>;
          };
          details.set(id, {
            summary: body.summary,
            details: body.details,
            aliases: body.aliases,
            severity: body.database_specific?.severity ?? body.severity?.[0]?.score,
          });
        } catch {
          /* keep the id-only finding */
        }
      }),
    );

    return findings.slice(0, 40).map((finding) => {
      const detail = details.get(finding.advisoryId);
      const sev = (detail?.severity ?? "").toUpperCase();
      let severity = finding.severity;
      if (sev === "CRITICAL" || sev === "HIGH" || sev === "MEDIUM" || sev === "LOW") {
        severity = sev;
      } else if (sev === "MODERATE") {
        severity = "MEDIUM";
      } else {
        const numeric = Number.parseFloat(detail?.severity ?? "");
        if (!Number.isNaN(numeric)) {
          severity = numeric >= 9 ? "CRITICAL" : numeric >= 7 ? "HIGH" : numeric >= 4 ? "MEDIUM" : "LOW";
        }
      }
      const cve = detail?.aliases?.find((alias) => alias.startsWith("CVE-"));
      return {
        ...finding,
        advisoryId: cve ?? finding.advisoryId,
        aliases: detail?.aliases ?? [],
        title: detail?.summary || finding.title,
        summary: (detail?.details ?? detail?.summary ?? "").slice(0, 500),
        severity,
      };
    });
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

function languagesFrom(part: PartFile, primary: string | null): string[] {
  const ranked = Object.entries(part.languageHints ?? {})
    .sort((a, b) => b[1] - a[1])
    .map(([ext]) => EXT_LANG[ext])
    .filter((name): name is string => Boolean(name));
  const unique = [...new Set(primary ? [primary, ...ranked] : ranked)];
  return unique.length > 0 ? unique : ["Unknown"];
}

function scanPart(part: PartFile, meta: RepoMeta | undefined): Omit<RepoSnapshot, "findingsCount" | "criticalCount" | "highCount"> & {
  findings: VulnerabilityFinding[];
} {
  const lockDeps: DependencyItem[] = [];
  const manifestDeps: DependencyItem[] = [];
  const runtimes: RuntimeSignal[] = [];
  const frameworks = new Set<string>();
  const dockerImages: string[] = [];
  const manifestsFound: string[] = [];

  for (const file of part.files ?? []) {
    const text = file.content ?? "";
    if (!text) continue;
    manifestsFound.push(file.path);
    const base = file.path.split("/").pop()?.toLowerCase() ?? "";
    if (base === "package.json") {
      const parsed = parsePackageJson(text, file.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
      parsed.frameworks.forEach((item) => frameworks.add(item));
    } else if (base === "package-lock.json") {
      lockDeps.push(...parsePackageLockJson(text, file.path));
    } else if (base === "composer.json") {
      const parsed = parseComposerJson(text, file.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
      parsed.frameworks.forEach((item) => frameworks.add(item));
    } else if (base === "composer.lock") {
      lockDeps.push(...parseComposerLock(text, file.path));
    } else if (base === "requirements.txt") {
      const parsed = parseRequirementsTxt(text, file.path);
      manifestDeps.push(...parsed.deps);
      parsed.frameworks.forEach((item) => frameworks.add(item));
    } else if (base === "pyproject.toml") {
      const parsed = parsePyprojectToml(text, file.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
      parsed.frameworks.forEach((item) => frameworks.add(item));
    } else if (base === "go.mod") {
      const parsed = parseGoMod(text, file.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
    } else if (base === "dockerfile") {
      const parsed = parseDockerfile(text, file.path);
      dockerImages.push(...parsed.dockerImages);
      runtimes.push(...parsed.runtimes);
    } else if (base === ".nvmrc" || base === ".node-version") {
      const ver = text.trim().split(/\r?\n/)[0]?.trim() ?? "";
      if (ver) {
        runtimes.push({
          runtime: "Node.js",
          version: ver,
          pinned: /\d+\.\d+/.test(ver),
          sourceFile: file.path,
        });
      }
    } else if (base === ".php-version") {
      const ver = text.trim().split(/\r?\n/)[0]?.trim() ?? "";
      if (ver) {
        runtimes.push({
          runtime: "PHP",
          version: ver,
          pinned: /\d+\.\d+/.test(ver),
          sourceFile: file.path,
        });
      }
    } else if (base === "wrangler.toml" || base === "wrangler.jsonc") {
      frameworks.add("Cloudflare Workers");
      const compatMatch = text.match(/compatibility_date\s*[:=]\s*["']([^"']+)["']/);
      if (compatMatch) {
        runtimes.push({
          runtime: "Cloudflare Workers",
          version: compatMatch[1],
          pinned: true,
          sourceFile: file.path,
        });
      }
    } else if (base === "build.gradle" || base === "build.gradle.kts") {
      frameworks.add("Android / Gradle");
    } else if (base === "cargo.toml") {
      frameworks.add("Rust");
    }
  }

  const dependencies = mergeDependencies(lockDeps, manifestDeps);
  const languages = languagesFrom(part, meta?.language ?? null);
  const ecosystems = new Set<string>(dependencies.map((d) => d.ecosystem));
  if (dockerImages.length > 0) ecosystems.add("Docker");
  if (languages.includes("PHP")) frameworks.add("PHP");

  const fullName = part.fullName;
  return {
    id: fullName,
    source: "github",
    fullName,
    htmlUrl: meta?.html_url ?? `https://github.com/${fullName}`,
    description: meta?.description ?? "",
    visibility: meta?.private ? "private" : "public",
    defaultBranch: meta?.default_branch ?? part.defaultBranch ?? "main",
    primaryLanguage: meta?.language ?? languages[0] ?? "Unknown",
    languages,
    frameworks: [...frameworks],
    ecosystems: [...ecosystems],
    runtimes,
    manifests: manifestsFound,
    dockerImages,
    dependencies,
    keyFiles: part.keyFiles ?? [],
    lastPushedAt: meta?.pushed_at ?? null,
    scannedAt: new Date().toISOString(),
    findings: [],
  };
}

async function mapLimit<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  async function next(): Promise<void> {
    while (cursor < items.length) {
      const idx = cursor++;
      results[idx] = await worker(items[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => next()));
  return results;
}

async function main(): Promise<void> {
  const metaRaw = JSON.parse(await readFile(META_PATH, "utf8")) as RepoMeta[][];
  const meta = new Map<string, RepoMeta>();
  for (const account of metaRaw) {
    for (const repo of account) meta.set(repo.full_name, repo);
  }

  const names = (await readdir(PARTS_DIR)).filter((name) => name.endsWith(".json"));
  const parts: PartFile[] = [];
  for (const name of names) {
    parts.push(JSON.parse(await readFile(path.join(PARTS_DIR, name), "utf8")) as PartFile);
  }

  const drafted = parts
    .filter((part) => part.fullName)
    .map((part) => scanPart(part, meta.get(part.fullName)))
    .sort((a, b) => a.fullName.localeCompare(b.fullName));

  const withFindings = await mapLimit(drafted, 4, async (repo) => {
    const findings = await queryOsv(repo.fullName, repo.dependencies);
    const hasNodeManifest = repo.manifests.some((item) => item.endsWith("package.json"));
    const hasPinnedNode = repo.runtimes.some((runtime) => runtime.runtime === "Node.js" && runtime.pinned);
    if (hasNodeManifest && !hasPinnedNode && !repo.frameworks.includes("Cloudflare Workers")) {
      findings.push({
        id: `${repo.fullName}::cfg-unpinned-runtime::node.js`.toLowerCase(),
        repoFullName: repo.fullName,
        advisoryId: "CFG-UNPINNED-RUNTIME",
        aliases: [],
        title: "Node.js Runtime Version Not Pinned in Git",
        summary:
          "No .nvmrc, .node-version, Dockerfile pin, or exact engines.node version was found. Runtime advisories will require checking your hosting provider settings.",
        severity: "LOW",
        category: "config",
        ecosystem: "Runtime",
        packageName: "node.js",
        installedVersion: "unpinned",
        fixedVersion: "Add .nvmrc or exact Dockerfile tag",
        manifestPath: repo.manifests.find((item) => item.endsWith("package.json")) ?? "package.json",
        referenceUrl: "",
        status: "open",
        detectedAt: new Date().toISOString(),
      });
    }
    const criticalCount = findings.filter((finding) => finding.severity === "CRITICAL").length;
    const highCount = findings.filter((finding) => finding.severity === "HIGH").length;
    const snapshot = { ...repo };
    delete snapshot.findings;
    return {
      snapshot: {
        ...snapshot,
        findingsCount: findings.length,
        criticalCount,
        highCount,
      },
      findings,
    };
  });

  const repos = withFindings.map((item) => item.snapshot);
  const findings = withFindings.flatMap((item) => item.findings);
  await writeFile(
    OUT_PATH,
    JSON.stringify(
      {
        scannedAt: new Date().toISOString(),
        repoCount: repos.length,
        findingCount: findings.length,
        repos,
        findings,
      },
      null,
      2,
    ),
  );
  console.log(
    JSON.stringify({
      repos: repos.length,
      deps: repos.reduce((sum, repo) => sum + repo.dependencies.length, 0),
      findings: findings.length,
      critical: findings.filter((finding) => finding.severity === "CRITICAL").length,
      high: findings.filter((finding) => finding.severity === "HIGH").length,
    }),
  );
}

await main();
