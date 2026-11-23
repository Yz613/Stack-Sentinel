import { isGitHubTokenConfigured, searchGitHubRepoCode } from "./github-scanner";
import { compareVersions } from "./manifests";
import {
  extractFixedVersion,
  extractReferenceUrl,
  fetchOsvAdvisoryById,
  parseOsvSeverity,
} from "./osv";
import { SAMPLE_CODE_EVIDENCE } from "./sample-fleet";
import type {
  ParsedAdvisory,
  RepoAdvisoryVerdict,
  RepoSnapshot,
  Severity,
} from "./types";

interface CuratedAdvisoryEntry {
  matchTerms: string[];
  advisory: Omit<ParsedAdvisory, "source">;
}

const CURATED_ADVISORIES: CuratedAdvisoryEntry[] = [
  {
    matchTerms: ["cve-2024-4577", "php-cgi", "php cgi"],
    advisory: {
      title: "PHP-CGI Argument Injection Vulnerability (CVE-2024-4577)",
      summary:
        "Argument injection in PHP-CGI on Windows/CGI deployments affecting PHP 8.3 < 8.3.8, 8.2 < 8.2.20, and 8.1 < 8.1.29. Requires checking PHP runtimes, Composer repos, and Docker PHP base images.",
      cveIds: ["CVE-2024-4577"],
      ecosystems: ["Packagist"],
      languages: ["PHP"],
      packages: [],
      frameworks: ["PHP", "Laravel", "Symfony", "WordPress"],
      dockerKeywords: ["php"],
      runtimeTargets: ["PHP"],
      configFiles: ["composer.json", "composer.lock", "Dockerfile", "public/index.php"],
      codePatterns: ["php-cgi", "php82-cgi", "cgi"],
      severity: "CRITICAL",
      referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
    },
  },
  {
    matchTerms: ["cve-2025-29927", "ghsa-f82v-jwr5-mffw", "next.js middleware", "nextjs middleware", "x-middleware-subrequest"],
    advisory: {
      title: "Next.js Middleware Authorization Bypass (CVE-2025-29927)",
      summary:
        "Attackers can bypass Next.js Middleware authorization checks by spoofing x-middleware-subrequest in Next.js < 14.2.25 and 15.x < 15.2.3. Exploitable when repos rely on middleware.ts/js for auth.",
      cveIds: ["CVE-2025-29927", "GHSA-f82v-jwr5-mffw"],
      ecosystems: ["npm"],
      languages: ["TypeScript", "JavaScript"],
      packages: [{ name: "next", ecosystem: "npm", affectedBelow: "14.2.25", fixedVersion: "14.2.25 / 15.2.3" }],
      frameworks: ["Next.js"],
      dockerKeywords: [],
      runtimeTargets: ["Node.js"],
      configFiles: ["middleware.ts", "src/middleware.ts", "middleware.js", "next.config.mjs", "next.config.ts"],
      codePatterns: ["middleware", "NextResponse", "x-middleware-subrequest"],
      severity: "CRITICAL",
      referenceUrl: "https://osv.dev/vulnerability/GHSA-f82v-jwr5-mffw",
    },
  },
  {
    matchTerms: ["cve-2025-27152", "ghsa-jr5f-v2jv-69x6", "axios ssrf", "axios credential"],
    advisory: {
      title: "Axios SSRF & Credential Leakage via Absolute URLs (CVE-2025-27152)",
      summary:
        "Axios < 1.8.2 can forward Authorization headers and hit unintended hosts when passed absolute or protocol-relative URLs alongside baseURL.",
      cveIds: ["CVE-2025-27152", "GHSA-jr5f-v2jv-69x6"],
      ecosystems: ["npm"],
      languages: ["TypeScript", "JavaScript"],
      packages: [{ name: "axios", ecosystem: "npm", affectedBelow: "1.8.2", fixedVersion: "1.8.2" }],
      frameworks: [],
      dockerKeywords: [],
      runtimeTargets: [],
      configFiles: ["package.json", "package-lock.json"],
      codePatterns: ["axios.create", "baseURL", "axios"],
      severity: "HIGH",
      referenceUrl: "https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6",
    },
  },
  {
    matchTerms: ["cve-2024-47874", "starlette", "fastapi dos", "fastapi multipart"],
    advisory: {
      title: "FastAPI / Starlette Multipart Form DoS (CVE-2024-47874)",
      summary:
        "Starlette < 0.40.0 (used by FastAPI) permits unbounded memory growth when parsing multipart form payloads.",
      cveIds: ["CVE-2024-47874", "GHSA-f96h-pmfr-66vw"],
      ecosystems: ["PyPI"],
      languages: ["Python"],
      packages: [
        { name: "starlette", ecosystem: "PyPI", affectedBelow: "0.40.0", fixedVersion: "0.40.0" },
        { name: "fastapi", ecosystem: "PyPI", affectedBelow: "0.115.2", fixedVersion: "0.115.2" },
      ],
      frameworks: ["FastAPI", "Starlette"],
      dockerKeywords: ["python"],
      runtimeTargets: ["Python"],
      configFiles: ["requirements.txt", "pyproject.toml"],
      codePatterns: ["FastAPI", "UploadFile", "Form("],
      severity: "HIGH",
      referenceUrl: "https://osv.dev/vulnerability/GHSA-f96h-pmfr-66vw",
    },
  },
  {
    matchTerms: ["alpine openssl", "docker alpine", "openssl"],
    advisory: {
      title: "Docker Alpine / OpenSSL Base Image Vulnerability",
      summary:
        "Container images built on Alpine Linux with OpenSSL require rebuilding against patched Alpine base tags and auditing installed apk openssl packages.",
      cveIds: [],
      ecosystems: ["Docker"],
      languages: [],
      packages: [],
      frameworks: [],
      dockerKeywords: ["alpine"],
      runtimeTargets: [],
      configFiles: ["Dockerfile"],
      codePatterns: ["alpine", "openssl"],
      severity: "HIGH",
      referenceUrl: "https://alpinelinux.org/posts/",
    },
  },
];

const ECOSYSTEM_KEYWORDS: Array<{
  terms: string[];
  ecosystem?: string;
  language?: string;
  framework?: string;
  runtime?: string;
  dockerKeyword?: string;
  configFiles?: string[];
}> = [
  {
    terms: ["php", "composer", "packagist", "laravel", "symfony", "wordpress", "php-fpm", "php-cgi"],
    ecosystem: "Packagist",
    language: "PHP",
    framework: "PHP",
    runtime: "PHP",
    dockerKeyword: "php",
    configFiles: ["composer.json", "composer.lock", "Dockerfile", "public/index.php"],
  },
  {
    terms: ["laravel"],
    ecosystem: "Packagist",
    language: "PHP",
    framework: "Laravel",
  },
  {
    terms: ["next.js", "nextjs", "next/"],
    ecosystem: "npm",
    language: "TypeScript",
    framework: "Next.js",
    runtime: "Node.js",
    configFiles: ["next.config.ts", "next.config.mjs", "src/middleware.ts", "middleware.ts"],
  },
  {
    terms: ["react", "jsx", "rsc", "server components"],
    ecosystem: "npm",
    language: "TypeScript",
    framework: "React",
  },
  {
    terms: ["node.js", "nodejs", "npm", "express", "javascript", "typescript"],
    ecosystem: "npm",
    language: "TypeScript",
    runtime: "Node.js",
    dockerKeyword: "node",
    configFiles: ["package.json", "package-lock.json", ".nvmrc"],
  },
  {
    terms: ["python", "pypi", "pip", "fastapi", "django", "flask", "starlette", "pydantic"],
    ecosystem: "PyPI",
    language: "Python",
    runtime: "Python",
    dockerKeyword: "python",
    configFiles: ["requirements.txt", "pyproject.toml", "Dockerfile"],
  },
  {
    terms: ["golang", "go.mod", "go stdlib", "go http", " go "],
    ecosystem: "Go",
    language: "Go",
    runtime: "Go",
    dockerKeyword: "golang",
    configFiles: ["go.mod", "Dockerfile"],
  },
  {
    terms: ["rust", "cargo", "crates.io"],
    ecosystem: "crates.io",
    language: "Rust",
    configFiles: ["Cargo.toml"],
  },
  {
    terms: ["android", "kotlin", "gradle", "okhttp", "webview"],
    ecosystem: "Gradle",
    language: "Kotlin",
    framework: "Android / Gradle",
    configFiles: ["app/build.gradle.kts", "AndroidManifest.xml"],
  },
  {
    terms: ["cloudflare", "wrangler", "workers", "hono"],
    ecosystem: "npm",
    framework: "Cloudflare Workers",
    runtime: "Cloudflare Workers",
    configFiles: ["wrangler.toml", "wrangler.jsonc"],
  },
  {
    terms: ["docker", "container", "alpine", "debian", "ubuntu", "openssl", "glibc"],
    ecosystem: "Docker",
    dockerKeyword: "alpine",
    configFiles: ["Dockerfile"],
  },
];

function extractIdsFromText(input: string): string[] {
  const matches = input.match(/\b(?:CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d{4}|PYSEC-\d{4}-\d{1,5})\b/gi);
  if (!matches) return [];
  return [...new Set(matches.map((m) => m.toUpperCase()))];
}

export async function parseAdvisoryInput(rawInput: string): Promise<ParsedAdvisory> {
  const input = rawInput.trim();
  const lower = ` ${input.toLowerCase()} `;
  const extractedIds = extractIdsFromText(input);

  // 1. Check curated high-signal advisories first for rich Stage 2 config/code patterns
  const curatedHit = CURATED_ADVISORIES.find((entry) =>
    entry.matchTerms.some((term) => lower.includes(term)),
  );

  // 2. If a CVE/GHSA/OSV ID is present, fetch live metadata from OSV.dev (no SSRF — hardcoded host)
  let osvData = null;
  for (const id of extractedIds.slice(0, 2)) {
    const fetched = await fetchOsvAdvisoryById(id);
    if (fetched) {
      osvData = fetched;
      break;
    }
  }

  if (osvData) {
    const packages: ParsedAdvisory["packages"] = [];
    const ecosystems = new Set<string>(curatedHit?.advisory.ecosystems ?? []);
    const languages = new Set<string>(curatedHit?.advisory.languages ?? []);

    for (const aff of osvData.affected ?? []) {
      const pkgName = aff.package?.name;
      const eco = aff.package?.ecosystem;
      if (eco) {
        ecosystems.add(eco);
        if (eco === "npm") {
          languages.add("TypeScript");
          languages.add("JavaScript");
        } else if (eco === "Packagist") {
          languages.add("PHP");
        } else if (eco === "PyPI") {
          languages.add("Python");
        } else if (eco === "Go") {
          languages.add("Go");
        }
      }
      if (pkgName) {
        const fixed = extractFixedVersion(osvData, pkgName);
        if (!packages.some((p) => p.name.toLowerCase() === pkgName.toLowerCase())) {
          packages.push({
            name: pkgName,
            ecosystem: eco,
            affectedBelow: fixed || undefined,
            fixedVersion: fixed || undefined,
          });
        }
      }
    }

    const cveIds = [
      ...new Set([
        ...extractedIds,
        osvData.id,
        ...(osvData.aliases ?? []).filter((a) => a.startsWith("CVE-") || a.startsWith("GHSA-")),
      ]),
    ].slice(0, 4);

    return {
      title: curatedHit?.advisory.title ?? osvData.summary ?? `Advisory ${cveIds[0] ?? osvData.id}`,
      summary: (osvData.summary || osvData.details || curatedHit?.advisory.summary || input).slice(0, 420),
      cveIds,
      ecosystems: [...ecosystems],
      languages: [...languages],
      packages: packages.length > 0 ? packages : (curatedHit?.advisory.packages ?? []),
      frameworks: curatedHit?.advisory.frameworks ?? [],
      dockerKeywords: curatedHit?.advisory.dockerKeywords ?? [],
      runtimeTargets: curatedHit?.advisory.runtimeTargets ?? [],
      configFiles: curatedHit?.advisory.configFiles ?? [],
      codePatterns:
        curatedHit?.advisory.codePatterns ??
        packages.slice(0, 2).map((p) => p.name),
      severity: parseOsvSeverity(osvData),
      source: "osv",
      referenceUrl: extractReferenceUrl(osvData) || curatedHit?.advisory.referenceUrl,
    };
  }

  if (curatedHit) {
    return {
      ...curatedHit.advisory,
      cveIds: [...new Set([...extractedIds, ...curatedHit.advisory.cveIds])],
      source: "curated",
    };
  }

  // 3. General plain-English heuristic extraction
  const ecosystems = new Set<string>();
  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const runtimeTargets = new Set<string>();
  const dockerKeywords = new Set<string>();
  const configFiles = new Set<string>();
  const packages: ParsedAdvisory["packages"] = [];

  for (const rule of ECOSYSTEM_KEYWORDS) {
    if (rule.terms.some((term) => lower.includes(term))) {
      if (rule.ecosystem) ecosystems.add(rule.ecosystem);
      if (rule.language) languages.add(rule.language);
      if (rule.framework) frameworks.add(rule.framework);
      if (rule.runtime) runtimeTargets.add(rule.runtime);
      if (rule.dockerKeyword) dockerKeywords.add(rule.dockerKeyword);
      rule.configFiles?.forEach((f) => configFiles.add(f));
    }
  }

  // Detect common named packages directly mentioned in prompt
  const knownPackages: Array<{ token: string; name: string; ecosystem: string }> = [
    { token: "next.js", name: "next", ecosystem: "npm" },
    { token: "nextjs", name: "next", ecosystem: "npm" },
    { token: "axios", name: "axios", ecosystem: "npm" },
    { token: "react", name: "react", ecosystem: "npm" },
    { token: "hono", name: "hono", ecosystem: "npm" },
    { token: "astro", name: "astro", ecosystem: "npm" },
    { token: "express", name: "express", ecosystem: "npm" },
    { token: "zod", name: "zod", ecosystem: "npm" },
    { token: "laravel", name: "laravel/framework", ecosystem: "Packagist" },
    { token: "symfony", name: "symfony/http-foundation", ecosystem: "Packagist" },
    { token: "guzzle", name: "guzzlehttp/guzzle", ecosystem: "Packagist" },
    { token: "fastapi", name: "fastapi", ecosystem: "PyPI" },
    { token: "starlette", name: "starlette", ecosystem: "PyPI" },
    { token: "pydantic", name: "pydantic", ecosystem: "PyPI" },
    { token: "httpx", name: "httpx", ecosystem: "PyPI" },
    { token: "okhttp", name: "com.squareup.okhttp3:okhttp", ecosystem: "Gradle" },
    { token: "x/crypto", name: "golang.org/x/crypto", ecosystem: "Go" },
    { token: "x/net", name: "golang.org/x/net", ecosystem: "Go" },
  ];

  for (const kp of knownPackages) {
    if (lower.includes(kp.token)) {
      ecosystems.add(kp.ecosystem);
      if (!packages.some((p) => p.name === kp.name)) {
        packages.push({ name: kp.name, ecosystem: kp.ecosystem });
      }
    }
  }

  const codePatterns = input
    .split(/[^a-zA-Z0-9._\/-]+/)
    .filter((w) => w.length >= 4 && !/^(this|that|with|from|into|does|check|make|sure|apply|repos|flaw|vulnerability|thing|comes|affect|affected|security|issue|advisory|https|http|github|com)$/i.test(w))
    .slice(0, 4);

  let severity: Severity = "MEDIUM";
  if (/rce|remote code|critical|auth bypass|zero-day|0-day|argument injection|sql injection/i.test(input)) {
    severity = "CRITICAL";
  } else if (/ssrf|xss|dos|denial of service|leak|high|privilege|csrf/i.test(input)) {
    severity = "HIGH";
  }

  const targetSummary =
    [...languages, ...frameworks, ...packages.map((p) => p.name), ...ecosystems].slice(0, 4).join(", ") ||
    "General stack";

  return {
    title:
      extractedIds.length > 0
        ? `Advisory Check: ${extractedIds[0]}`
        : `Advisory Check: ${input.slice(0, 72)}${input.length > 72 ? "..." : ""}`,
    summary: `Parsed targets (${targetSummary}) from your advisory query and evaluated all indexed repositories across manifests, lockfiles, Docker images, and runtime signals.`,
    cveIds: extractedIds,
    ecosystems: [...ecosystems],
    languages: [...languages],
    packages,
    frameworks: [...frameworks],
    dockerKeywords: [...dockerKeywords],
    runtimeTargets: [...runtimeTargets],
    configFiles: [...configFiles],
    codePatterns,
    severity,
    source: "heuristic",
  };
}

function isNextJsCve202529927Affected(version: string): boolean {
  const cmp15 = compareVersions(version, "15.0.0");
  if (cmp15 !== null && cmp15 >= 0) {
    const cmp15Fix = compareVersions(version, "15.2.3");
    return cmp15Fix !== null && cmp15Fix < 0;
  }
  const cmp14Fix = compareVersions(version, "14.2.25");
  return cmp14Fix !== null && cmp14Fix < 0;
}

function isPhpCve20244577Affected(version: string): boolean {
  const numeric = version.match(/(\d+\.\d+\.\d+)/)?.[1];
  if (!numeric) return true;
  if (numeric.startsWith("8.3.")) {
    const c = compareVersions(numeric, "8.3.8");
    return c !== null && c < 0;
  }
  if (numeric.startsWith("8.2.")) {
    const c = compareVersions(numeric, "8.2.20");
    return c !== null && c < 0;
  }
  if (numeric.startsWith("8.1.")) {
    const c = compareVersions(numeric, "8.1.29");
    return c !== null && c < 0;
  }
  return false;
}

export async function evaluateAdvisoryAgainstFleet(
  parsed: ParsedAdvisory,
  repos: RepoSnapshot[],
  runStage2: boolean,
): Promise<RepoAdvisoryVerdict[]> {
  const verdicts: RepoAdvisoryVerdict[] = [];
  const hasLiveGitHub = isGitHubTokenConfigured();

  const lowerTargets = {
    ecosystems: new Set(parsed.ecosystems.map((e) => e.toLowerCase())),
    languages: new Set(parsed.languages.map((l) => l.toLowerCase())),
    frameworks: new Set(parsed.frameworks.map((f) => f.toLowerCase())),
    runtimes: new Set(parsed.runtimeTargets.map((r) => r.toLowerCase())),
    docker: parsed.dockerKeywords.map((d) => d.toLowerCase()),
    packages: parsed.packages.map((p) => ({ ...p, lowerName: p.name.toLowerCase() })),
    configFiles: parsed.configFiles.map((f) => f.toLowerCase()),
    patterns: parsed.codePatterns.map((p) => p.toLowerCase()),
  };

  const hasSpecificFilter =
    lowerTargets.ecosystems.size > 0 ||
    lowerTargets.languages.size > 0 ||
    lowerTargets.frameworks.size > 0 ||
    lowerTargets.runtimes.size > 0 ||
    lowerTargets.docker.length > 0 ||
    lowerTargets.packages.length > 0;

  let liveCodeSearchCalls = 0;

  for (const repo of repos) {
    const repoLangs = repo.languages.map((l) => l.toLowerCase());
    const repoEcosystems = repo.ecosystems.map((e) => e.toLowerCase());
    const repoFrameworks = repo.frameworks.map((f) => f.toLowerCase());
    const repoRuntimes = repo.runtimes.map((r) => r.runtime.toLowerCase());
    const repoDocker = repo.dockerImages.map((d) => d.toLowerCase());

    // Match packages directly in SBOM
    const matchedPackages: RepoAdvisoryVerdict["matchedPackages"] = [];
    let hasConfirmedVulnerablePkg = false;
    let hasPatchedPkg = false;

    for (const targetPkg of lowerTargets.packages) {
      const dep = repo.dependencies.find(
        (d) =>
          d.name.toLowerCase() === targetPkg.lowerName ||
          d.name.toLowerCase().endsWith(`/${targetPkg.lowerName}`),
      );
      if (!dep) continue;

      matchedPackages.push({
        name: dep.name,
        installedVersion: dep.version,
        fixedVersion: targetPkg.fixedVersion,
        ecosystem: dep.ecosystem,
        manifestPath: dep.manifestPath,
      });

      if (parsed.cveIds.includes("CVE-2025-29927") && dep.name.toLowerCase() === "next") {
        if (isNextJsCve202529927Affected(dep.version)) {
          hasConfirmedVulnerablePkg = true;
        } else {
          hasPatchedPkg = true;
        }
      } else if (targetPkg.affectedBelow) {
        const cmp = compareVersions(dep.version, targetPkg.affectedBelow);
        if (cmp !== null && cmp < 0) {
          hasConfirmedVulnerablePkg = true;
        } else if (cmp !== null && cmp >= 0) {
          hasPatchedPkg = true;
        }
      }
    }

    const langMatch = repoLangs.some((l) => lowerTargets.languages.has(l));
    const ecoMatch = repoEcosystems.some(
      (e) =>
        lowerTargets.ecosystems.has(e) &&
        !(e === "docker" && lowerTargets.docker.length > 0),
    );
    const frameworkMatch = repoFrameworks.some((f) => lowerTargets.frameworks.has(f));
    const runtimeMatch = repoRuntimes.some((r) => lowerTargets.runtimes.has(r));
    const dockerMatch = repoDocker.some((img) =>
      lowerTargets.docker.some((kw) => img.includes(kw)),
    );

    // Stage 1: Deterministic Fleet Filter
    if (lowerTargets.packages.length > 0 && matchedPackages.length === 0) {
      // Advisory targets specific package(s), and this repo doesn't depend on any of them
      const stackDesc = [repo.primaryLanguage, ...repo.frameworks.slice(0, 2)].filter(Boolean).join(" / ");
      verdicts.push({
        repoFullName: repo.fullName,
        htmlUrl: repo.htmlUrl,
        primaryLanguage: repo.primaryLanguage,
        frameworks: repo.frameworks,
        verdict: "cleared",
        confidence: "high",
        stage1Outcome: "cleared",
        stage1Reason: `Cleared in Stage 1 — ${stackDesc || "Repo"} does not include ${lowerTargets.packages.map((p) => p.name).join(", ")} in any indexed manifest or lockfile.`,
        matchedPackages: [],
        stage2: {
          executed: false,
          mode: "skipped",
          reachability: "not_applicable",
          matchedFiles: [],
          codeHits: [],
          notes: ["Skipped Stage 2 because target packages are absent from SBOM."],
        },
        remediation: "No action required.",
      });
      continue;
    }

    if (
      hasSpecificFilter &&
      matchedPackages.length === 0 &&
      !langMatch &&
      !ecoMatch &&
      !frameworkMatch &&
      !runtimeMatch &&
      !dockerMatch
    ) {
      const expectedStack =
        [...parsed.languages, ...parsed.frameworks, ...parsed.ecosystems].slice(0, 3).join("/") ||
        "target stack";
      const actualStack =
        [repo.primaryLanguage, ...repo.frameworks.slice(0, 2)].filter(Boolean).join(" / ") ||
        "Unknown stack";
      verdicts.push({
        repoFullName: repo.fullName,
        htmlUrl: repo.htmlUrl,
        primaryLanguage: repo.primaryLanguage,
        frameworks: repo.frameworks,
        verdict: "cleared",
        confidence: "high",
        stage1Outcome: "cleared",
        stage1Reason: `Cleared in Stage 1 — ${actualStack} repo has no ${expectedStack} runtime, manifests, or container base image.`,
        matchedPackages: [],
        stage2: {
          executed: false,
          mode: "skipped",
          reachability: "not_applicable",
          matchedFiles: [],
          codeHits: [],
          notes: ["Eliminated deterministically by stack & SBOM fingerprint."],
        },
        remediation: "No action required.",
      });
      continue;
    }

    // If package exists but installed version is already >= fixed version, clear with high confidence!
    if (matchedPackages.length > 0 && hasPatchedPkg && !hasConfirmedVulnerablePkg) {
      const pkgSummary = matchedPackages
        .map((m) => `${m.name}@${m.installedVersion} (fixed in ${m.fixedVersion ?? "latest"})`)
        .join(", ");
      verdicts.push({
        repoFullName: repo.fullName,
        htmlUrl: repo.htmlUrl,
        primaryLanguage: repo.primaryLanguage,
        frameworks: repo.frameworks,
        verdict: "cleared",
        confidence: "high",
        stage1Outcome: "cleared",
        stage1Reason: `Cleared in Stage 1 — uses patched version ${pkgSummary}.`,
        matchedPackages,
        stage2: {
          executed: false,
          mode: "skipped",
          reachability: "not_applicable",
          matchedFiles: [],
          codeHits: [],
          notes: ["Installed lockfile version is at or above the patched release."],
        },
        remediation: "Already on a patched version; no upgrade needed.",
      });
      continue;
    }

    // Candidate passed Stage 1 -> prepare Stage 2 triage
    const matchedFiles = repo.keyFiles.filter((file) => {
      const fl = file.toLowerCase();
      return lowerTargets.configFiles.some((cfg) => fl.endsWith(cfg) || fl.includes(cfg));
    });

    const stage2Notes: string[] = [];
    const codeHits: Array<{ path: string; snippet: string; pattern: string }> = [];
    let stage2Mode: RepoAdvisoryVerdict["stage2"]["mode"] = "skipped";
    let reachability: RepoAdvisoryVerdict["stage2"]["reachability"] = "likely";

    if (runStage2) {
      if (repo.source === "github" && hasLiveGitHub && liveCodeSearchCalls < 6 && parsed.codePatterns.length > 0) {
        stage2Mode = "live_github";
        liveCodeSearchCalls++;
        const liveHits = await searchGitHubRepoCode(repo.fullName, parsed.codePatterns[0]);
        codeHits.push(...liveHits);
      } else {
        stage2Mode = "indexed_heuristic";
        const sampleEvidence = SAMPLE_CODE_EVIDENCE[repo.fullName] ?? [];
        const searchTokens = [
          ...parsed.cveIds.map((c) => c.toLowerCase()),
          ...lowerTargets.patterns,
          ...lowerTargets.packages.map((p) => p.lowerName),
          ...lowerTargets.docker,
          ...lowerTargets.languages,
        ];
        for (const ev of sampleEvidence) {
          const hitTag = ev.tags.find((t) => searchTokens.some((st) => st.includes(t) || t.includes(st)));
          if (hitTag) {
            codeHits.push({ path: ev.path, snippet: ev.snippet, pattern: hitTag });
          }
        }
      }

      if (matchedFiles.length > 0) {
        stage2Notes.push(`Relevant security/config files present: ${matchedFiles.join(", ")}.`);
      }

      // Check runtime pinning blind spots
      const matchedRuntimeObj = repo.runtimes.find((r) =>
        lowerTargets.runtimes.has(r.runtime.toLowerCase()),
      );
      if (lowerTargets.runtimes.size > 0 && (!matchedRuntimeObj || !matchedRuntimeObj.pinned)) {
        stage2Notes.push(
          `Runtime blind spot: ${[...parsed.runtimeTargets].join("/")} version is not pinned to an exact patch release in git; confirm the production runtime version on your host.`,
        );
        reachability = "unverified_runtime";
      }

      // Special reachability logic for PHP-CGI CVE-2024-4577
      if (parsed.cveIds.includes("CVE-2024-4577") || lowerTargets.languages.has("php")) {
        const phpRuntime = repo.runtimes.find((r) => r.runtime.toLowerCase() === "php");
        const hasCgiHit = codeHits.some((h) => h.snippet.toLowerCase().includes("cgi"));
        if (phpRuntime && isPhpCve20244577Affected(phpRuntime.version) && hasCgiHit) {
          hasConfirmedVulnerablePkg = true;
          reachability = "confirmed";
          stage2Notes.push(
            `Dockerfile pins PHP ${phpRuntime.version} and installs a CGI binary (php-cgi).`,
          );
        } else if (phpRuntime) {
          stage2Notes.push(
            `Detected PHP runtime (${phpRuntime.version} in ${phpRuntime.sourceFile}). Verify CGI mode is disabled in production.`,
          );
        }
      }

      // Special reachability logic for Next.js Middleware CVE-2025-29927
      if (parsed.cveIds.includes("CVE-2025-29927")) {
        const hasMiddleware = repo.keyFiles.some((f) => /middleware\.(ts|js|mjs)$/i.test(f));
        if (hasMiddleware) {
          reachability = "confirmed";
          stage2Notes.push("Confirmed custom Next.js middleware file in repository — directly reachable.");
        } else {
          reachability = "likely";
          stage2Notes.push("No root/src middleware.ts found; lower direct exposure, but upgrading Next.js is still recommended.");
        }
      } else if (codeHits.length > 0 && reachability !== "unverified_runtime") {
        reachability = "confirmed";
        stage2Notes.push(`Found ${codeHits.length} matching code/config reference(s) for advisory patterns.`);
      }
    }

    const isAffected = hasConfirmedVulnerablePkg || (matchedPackages.length > 0 && reachability === "confirmed");
    const verdict: RepoAdvisoryVerdict["verdict"] = isAffected ? "affected" : "needs_review";
    const stage1Outcome: RepoAdvisoryVerdict["stage1Outcome"] = isAffected
      ? "direct_match"
      : "candidate";

    const stage1Reasons: string[] = [];
    if (matchedPackages.length > 0) {
      stage1Reasons.push(
        `Matched package(s): ${matchedPackages.map((m) => `${m.name}@${m.installedVersion}`).join(", ")}`,
      );
    }
    if (dockerMatch) {
      stage1Reasons.push(`Matched Docker base image: ${repo.dockerImages.join(", ")}`);
    }
    if (langMatch || frameworkMatch) {
      stage1Reasons.push(
        `Matched stack: ${[repo.primaryLanguage, ...repo.frameworks].filter(Boolean).slice(0, 3).join(", ")}`,
      );
    }
    if (stage1Reasons.length === 0) {
      stage1Reasons.push("Generic advisory query with no narrow ecosystem filter; flagged for manual triage.");
    }

    let remediation = "Review matched files and verify dependency/runtime patch levels.";
    if (matchedPackages.some((m) => m.fixedVersion)) {
      const upgrades = matchedPackages
        .filter((m) => m.fixedVersion)
        .map((m) => `upgrade ${m.name} from ${m.installedVersion} to ${m.fixedVersion}`)
        .join("; ");
      remediation = `Action required: ${upgrades}.`;
    } else if (dockerMatch) {
      remediation = `Rebuild container from latest patched base image (${repo.dockerImages[0]}) and verify installed packages.`;
    } else if (lowerTargets.runtimes.size > 0) {
      remediation = `Confirm deployed ${[...parsed.runtimeTargets].join("/")} patch version in hosting provider and pin it in git.`;
    }

    verdicts.push({
      repoFullName: repo.fullName,
      htmlUrl: repo.htmlUrl,
      primaryLanguage: repo.primaryLanguage,
      frameworks: repo.frameworks,
      verdict,
      confidence: isAffected ? "high" : matchedPackages.length > 0 || dockerMatch ? "medium" : "low",
      stage1Outcome,
      stage1Reason: stage1Reasons.join(" · "),
      matchedPackages,
      stage2: {
        executed: runStage2,
        mode: stage2Mode,
        reachability,
        matchedFiles,
        codeHits,
        notes: stage2Notes.length > 0 ? stage2Notes : ["No automated code hits; inspect matched manifests/configs."],
      },
      remediation,
    });
  }

  // Sort: affected first, then needs_review, then cleared
  const order = { affected: 0, needs_review: 1, cleared: 2 };
  verdicts.sort((a, b) => order[a.verdict] - order[b.verdict] || a.repoFullName.localeCompare(b.repoFullName));
  return verdicts;
}
