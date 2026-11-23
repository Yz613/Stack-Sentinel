import { getWorkerSecret } from "./cf-env";
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
} from "./manifests";
import { queryOsvForDependencies } from "./osv";
import { safeExternalUrl } from "./security";
import type { DependencyItem, RepoSnapshot, RuntimeSignal, VulnerabilityFinding } from "./types";

const GITHUB_API_BASE = "https://api.github.com";
const MAX_REPOS_PER_SCAN = 50;
const MAX_FILE_BYTES = 1_500_000;
const REPO_SCAN_CONCURRENCY = 5;

const MANIFEST_NAMES = new Set([
  "package.json",
  "package-lock.json",
  "composer.json",
  "composer.lock",
  "requirements.txt",
  "pyproject.toml",
  "go.mod",
  "cargo.toml",
  "dockerfile",
  ".nvmrc",
  ".node-version",
  ".php-version",
  "wrangler.toml",
  "wrangler.jsonc",
  "build.gradle",
  "build.gradle.kts",
]);

const KEY_SECURITY_FILE_RE =
  /(^|\/)(middleware\.(ts|js|mjs)|next\.config\.(ts|js|mjs)|dockerfile|docker-compose\.ya?ml|wrangler\.(toml|jsonc)|composer\.json|package\.json|requirements\.txt|pyproject\.toml|go\.mod|public\/index\.php|\.nvmrc|\.php-version|androidmanifest\.xml)$/i;

interface GitHubRepoApi {
  full_name: string;
  html_url: string;
  description: string | null;
  private: boolean;
  archived: boolean;
  default_branch: string;
  language: string | null;
  pushed_at: string | null;
  size: number;
}

interface GitHubTreeItem {
  path?: string;
  type?: string;
  size?: number;
}

export function isGitHubTokenConfigured(): boolean {
  return Boolean(getWorkerSecret("GITHUB_TOKEN"));
}

function getGitHubHeaders(tokenOverride?: string): Record<string, string> {
  const token = tokenOverride?.trim() || getWorkerSecret("GITHUB_TOKEN");
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": "StackSentinel-Security-Scanner",
  };
  if (token) {
    headers.authorization = `Bearer ${token}`;
  }
  return headers;
}

async function githubFetchJson<T>(
  path: string,
  timeoutMs = 8000,
  tokenOverride?: string,
): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${GITHUB_API_BASE}${path}`, {
      method: "GET",
      headers: getGitHubHeaders(tokenOverride),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchRepoFileText(
  owner: string,
  repo: string,
  filePath: string,
  tokenOverride?: string,
): Promise<string | null> {
  const encodedPath = filePath
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  const data = await githubFetchJson<{ content?: string; encoding?: string; size?: number }>(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}`,
    8000,
    tokenOverride,
  );
  if (!data?.content || data.encoding !== "base64") return null;
  if (typeof data.size === "number" && data.size > MAX_FILE_BYTES) return null;
  try {
    const cleaned = data.content.replace(/\s+/g, "");
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return null;
  }
}

async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
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

async function scanSingleGitHubRepo(
  ownerSub: string,
  repo: GitHubRepoApi,
  tokenOverride?: string,
): Promise<{ snapshot: RepoSnapshot; findings: VulnerabilityFinding[] }> {
  const [owner, name] = repo.full_name.split("/");
  const languagesMap = await githubFetchJson<Record<string, number>>(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/languages`,
    8000,
    tokenOverride,
  );
  const languages = languagesMap
    ? Object.keys(languagesMap)
    : repo.language
      ? [repo.language]
      : [];

  const treeData = await githubFetchJson<{ tree?: GitHubTreeItem[]; truncated?: boolean }>(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/git/trees/${encodeURIComponent(repo.default_branch)}?recursive=1`,
    8000,
    tokenOverride,
  );

  const blobPaths = (treeData?.tree ?? [])
    .filter((item) => item.type === "blob" && typeof item.path === "string")
    .filter((item) => !item.path!.includes("node_modules/") && !item.path!.includes("vendor/"))
    .map((item) => ({ path: item.path!, size: item.size ?? 0 }));

  const keyFiles = blobPaths
    .map((b) => b.path)
    .filter((p) => KEY_SECURITY_FILE_RE.test(p))
    .slice(0, 35);

  // Pick root or shallow manifest files (depth <= 2) to keep scan fast and bounded
  const manifestCandidates = blobPaths
    .filter((b) => {
      const depth = b.path.split("/").length - 1;
      const base = b.path.split("/").pop()?.toLowerCase() ?? "";
      return depth <= 2 && MANIFEST_NAMES.has(base) && b.size <= MAX_FILE_BYTES;
    })
    .slice(0, 12);

  const lockDeps: DependencyItem[] = [];
  const manifestDeps: DependencyItem[] = [];
  const runtimes: RuntimeSignal[] = [];
  const frameworks = new Set<string>();
  const dockerImages: string[] = [];
  const manifestsFound: string[] = [];

  for (const candidate of manifestCandidates) {
    const text = await fetchRepoFileText(owner, name, candidate.path, tokenOverride);
    if (!text) continue;
    manifestsFound.push(candidate.path);
    const base = candidate.path.split("/").pop()?.toLowerCase() ?? "";

    if (base === "package.json") {
      const parsed = parsePackageJson(text, candidate.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
      parsed.frameworks.forEach((f) => frameworks.add(f));
    } else if (base === "package-lock.json") {
      lockDeps.push(...parsePackageLockJson(text, candidate.path));
    } else if (base === "composer.json") {
      const parsed = parseComposerJson(text, candidate.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
      parsed.frameworks.forEach((f) => frameworks.add(f));
    } else if (base === "composer.lock") {
      lockDeps.push(...parseComposerLock(text, candidate.path));
    } else if (base === "requirements.txt") {
      const parsed = parseRequirementsTxt(text, candidate.path);
      manifestDeps.push(...parsed.deps);
      parsed.frameworks.forEach((f) => frameworks.add(f));
    } else if (base === "pyproject.toml") {
      const parsed = parsePyprojectToml(text, candidate.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
      parsed.frameworks.forEach((f) => frameworks.add(f));
    } else if (base === "go.mod") {
      const parsed = parseGoMod(text, candidate.path);
      manifestDeps.push(...parsed.deps);
      runtimes.push(...parsed.runtimes);
    } else if (base === "dockerfile") {
      const parsed = parseDockerfile(text, candidate.path);
      dockerImages.push(...parsed.dockerImages);
      runtimes.push(...parsed.runtimes);
    } else if (base === ".nvmrc" || base === ".node-version") {
      const ver = text.trim().split(/\r?\n/)[0]?.trim() ?? "";
      if (ver) {
        runtimes.push({
          runtime: "Node.js",
          version: ver,
          pinned: /\d+\.\d+/.test(ver),
          sourceFile: candidate.path,
        });
      }
    } else if (base === ".php-version") {
      const ver = text.trim().split(/\r?\n/)[0]?.trim() ?? "";
      if (ver) {
        runtimes.push({
          runtime: "PHP",
          version: ver,
          pinned: /\d+\.\d+/.test(ver),
          sourceFile: candidate.path,
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
          sourceFile: candidate.path,
        });
      }
    } else if (base === "build.gradle" || base === "build.gradle.kts") {
      frameworks.add("Android / Gradle");
    }
  }

  const dependencies = mergeDependencies(lockDeps, manifestDeps);
  const ecosystems = new Set<string>(dependencies.map((d) => d.ecosystem));
  if (dockerImages.length > 0) ecosystems.add("Docker");
  if (languages.includes("PHP")) frameworks.add("PHP");

  const findings = await queryOsvForDependencies(repo.full_name, dependencies);

  // Flag unpinned Node/PHP runtime when an app has web manifests without any version pin
  const hasNodeManifest = manifestsFound.some((m) => m.endsWith("package.json"));
  const hasPinnedNode = runtimes.some((r) => r.runtime === "Node.js" && r.pinned);
  if (hasNodeManifest && !hasPinnedNode && !frameworks.has("Cloudflare Workers")) {
    findings.push({
      id: `${repo.full_name}::cfg-unpinned-runtime::node.js`.toLowerCase(),
      repoFullName: repo.full_name,
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
      manifestPath: manifestsFound.find((m) => m.endsWith("package.json")) ?? "package.json",
      referenceUrl: "",
      status: "open",
      detectedAt: new Date().toISOString(),
    });
  }

  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;

  const snapshot: RepoSnapshot = {
    id: `${ownerSub}:${repo.full_name}`,
    source: "github",
    fullName: repo.full_name,
    htmlUrl: safeExternalUrl(repo.html_url),
    description: repo.description ?? "",
    visibility: repo.private ? "private" : "public",
    defaultBranch: repo.default_branch,
    primaryLanguage: repo.language ?? languages[0] ?? "Unknown",
    languages,
    frameworks: [...frameworks],
    ecosystems: [...ecosystems],
    runtimes,
    manifests: manifestsFound,
    dockerImages,
    dependencies,
    keyFiles,
    findingsCount: findings.length,
    criticalCount,
    highCount,
    lastPushedAt: repo.pushed_at,
    scannedAt: new Date().toISOString(),
  };

  return { snapshot, findings };
}

export async function fetchGitHubUser(
  token: string,
): Promise<{ login: string; avatarUrl: string } | null> {
  const user = await githubFetchJson<{ login?: string; avatar_url?: string }>(
    "/user",
    8000,
    token,
  );
  if (!user?.login) return null;
  return {
    login: user.login,
    avatarUrl: user.avatar_url ?? "",
  };
}

export async function scanLiveGitHubFleet(
  ownerSub: string,
  tokenOverride?: string,
): Promise<{ repos: RepoSnapshot[]; findings: VulnerabilityFinding[] }> {
  const apiRepos = await githubFetchJson<GitHubRepoApi[]>(
    `/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member`,
    12000,
    tokenOverride,
  );
  if (!apiRepos || !Array.isArray(apiRepos)) {
    throw new Error("Unable to fetch repositories from GitHub API. Check your GitHub token and permissions.");
  }

  const activeRepos = apiRepos.filter((r) => !r.archived).slice(0, MAX_REPOS_PER_SCAN);
  const scanned = await runWithConcurrency(activeRepos, REPO_SCAN_CONCURRENCY, (repo) =>
    scanSingleGitHubRepo(ownerSub, repo, tokenOverride),
  );

  const repos: RepoSnapshot[] = [];
  const findings: VulnerabilityFinding[] = [];
  for (const item of scanned) {
    repos.push(item.snapshot);
    findings.push(...item.findings);
  }
  return { repos, findings };
}

/**
 * Stage 2 targeted GitHub Code Search inside one specific repository.
 */
export async function searchGitHubRepoCode(
  repoFullName: string,
  pattern: string,
): Promise<Array<{ path: string; snippet: string; pattern: string }>> {
  if (!isGitHubTokenConfigured()) return [];
  const sanitizedPattern = pattern.replace(/["\\]/g, "").trim().slice(0, 60);
  if (!sanitizedPattern || !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repoFullName)) {
    return [];
  }

  const q = encodeURIComponent(`${sanitizedPattern} repo:${repoFullName}`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(`${GITHUB_API_BASE}/search/code?q=${q}&per_page=3`, {
      method: "GET",
      headers: {
        ...getGitHubHeaders(),
        accept: "application/vnd.github.text-match+json",
      },
      signal: controller.signal,
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      items?: Array<{
        path?: string;
        text_matches?: Array<{ fragment?: string }>;
      }>;
    };
    return (data.items ?? [])
      .filter((item) => typeof item.path === "string")
      .map((item) => ({
        path: item.path!,
        snippet: (item.text_matches?.[0]?.fragment ?? `Matched '${sanitizedPattern}'`).slice(0, 220),
        pattern: sanitizedPattern,
      }));
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}
