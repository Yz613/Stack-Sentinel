import fleetSeed from "@/data/github-fleet.json";
import { evaluateAdvisoryAgainstFleet, parseAdvisoryInput } from "./advisory-engine";
import { dbAll, dbBatch, dbRun } from "./db";
import { isGitHubTokenConfigured, scanLiveGitHubFleet } from "./github-scanner";
import { buildSampleFindings, buildSampleRepos } from "./sample-fleet";
import type {
  AdvisoryCheckRun,
  FindingCategory,
  FindingStatus,
  ParsedAdvisory,
  RepoAdvisoryVerdict,
  RepoSnapshot,
  ScanRunRecord,
  Severity,
  VulnerabilityFinding,
} from "./types";

function parseJsonSafe<T>(raw: string, fallback: T): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

interface RepoRow {
  id: string;
  source: "github" | "sample";
  full_name: string;
  html_url: string;
  description: string;
  visibility: string;
  default_branch: string;
  primary_language: string;
  languages_json: string;
  frameworks_json: string;
  ecosystems_json: string;
  runtimes_json: string;
  manifests_json: string;
  docker_images_json: string;
  dependencies_json: string;
  key_files_json: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  last_pushed_at: string | null;
  scanned_at: string;
}

interface FindingRow {
  id: string;
  repo_full_name: string;
  advisory_id: string;
  aliases_json: string;
  title: string;
  summary: string;
  severity: Severity;
  category: FindingCategory;
  ecosystem: string;
  package_name: string;
  installed_version: string;
  fixed_version: string;
  manifest_path: string;
  reference_url: string;
  status: FindingStatus;
  detected_at: string;
}

interface AdvisoryCheckRow {
  id: string;
  query_input: string;
  parsed_summary: string;
  parsed_json: string;
  total_repos: number;
  affected_count: number;
  needs_review_count: number;
  cleared_count: number;
  results_json: string;
  created_at: string;
}

interface ScanRunRow {
  id: string;
  mode: "github" | "sample";
  repos_scanned: number;
  dependencies_indexed: number;
  findings_detected: number;
  duration_ms: number;
  created_at: string;
}

function mapRepoRow(row: RepoRow): RepoSnapshot {
  return {
    id: row.id,
    source: row.source,
    fullName: row.full_name,
    htmlUrl: row.html_url,
    description: row.description,
    visibility: row.visibility,
    defaultBranch: row.default_branch,
    primaryLanguage: row.primary_language,
    languages: parseJsonSafe(row.languages_json, []),
    frameworks: parseJsonSafe(row.frameworks_json, []),
    ecosystems: parseJsonSafe(row.ecosystems_json, []),
    runtimes: parseJsonSafe(row.runtimes_json, []),
    manifests: parseJsonSafe(row.manifests_json, []),
    dockerImages: parseJsonSafe(row.docker_images_json, []),
    dependencies: parseJsonSafe(row.dependencies_json, []),
    keyFiles: parseJsonSafe(row.key_files_json, []),
    findingsCount: Number(row.findings_count),
    criticalCount: Number(row.critical_count),
    highCount: Number(row.high_count),
    lastPushedAt: row.last_pushed_at,
    scannedAt: String(row.scanned_at),
  };
}

function mapFindingRow(row: FindingRow): VulnerabilityFinding {
  return {
    id: row.id,
    repoFullName: row.repo_full_name,
    advisoryId: row.advisory_id,
    aliases: parseJsonSafe(row.aliases_json, []),
    title: row.title,
    summary: row.summary,
    severity: row.severity,
    category: row.category,
    ecosystem: row.ecosystem,
    packageName: row.package_name,
    installedVersion: row.installed_version,
    fixedVersion: row.fixed_version,
    manifestPath: row.manifest_path,
    referenceUrl: row.reference_url,
    status: row.status,
    detectedAt: String(row.detected_at),
  };
}

function mapAdvisoryCheckRow(row: AdvisoryCheckRow): AdvisoryCheckRun {
  return {
    id: row.id,
    queryInput: row.query_input,
    parsedSummary: row.parsed_summary,
    parsed: parseJsonSafe<ParsedAdvisory>(row.parsed_json, {
      title: row.query_input,
      summary: row.parsed_summary,
      cveIds: [],
      ecosystems: [],
      languages: [],
      packages: [],
      frameworks: [],
      dockerKeywords: [],
      runtimeTargets: [],
      configFiles: [],
      codePatterns: [],
      severity: "MEDIUM",
      source: "heuristic",
    }),
    totalRepos: Number(row.total_repos),
    affectedCount: Number(row.affected_count),
    needsReviewCount: Number(row.needs_review_count),
    clearedCount: Number(row.cleared_count),
    results: parseJsonSafe<RepoAdvisoryVerdict[]>(row.results_json, []),
    createdAt: String(row.created_at),
  };
}

async function persistFleetSnapshot(
  ownerSub: string,
  mode: "github" | "sample",
  repos: RepoSnapshot[],
  findings: VulnerabilityFinding[],
  durationMs: number,
): Promise<ScanRunRecord> {
  const priorStatuses = await dbAll<{ id: string; status: FindingStatus }>(
    "SELECT id, status FROM vulnerability_findings WHERE owner_sub = ?",
    [ownerSub],
  );
  const statusMap = new Map(priorStatuses.map((r) => [r.id, r.status]));

  const countsByRepo = new Map<string, { total: number; critical: number; high: number }>();
  for (const f of findings) {
    const scopedId = `${ownerSub}::${f.id}`;
    const effectiveStatus = statusMap.get(scopedId) ?? f.status;
    if (effectiveStatus === "dismissed") continue;
    const cur = countsByRepo.get(f.repoFullName) ?? { total: 0, critical: 0, high: 0 };
    cur.total++;
    if (f.severity === "CRITICAL") cur.critical++;
    if (f.severity === "HIGH") cur.high++;
    countsByRepo.set(f.repoFullName, cur);
  }

  const nowIso = new Date().toISOString();
  const statements: Array<{ sql: string; params?: unknown[] }> = [
    { sql: "DELETE FROM repo_snapshots WHERE owner_sub = ?", params: [ownerSub] },
    { sql: "DELETE FROM vulnerability_findings WHERE owner_sub = ?", params: [ownerSub] },
  ];

  for (const repo of repos) {
    const counts = countsByRepo.get(repo.fullName) ?? { total: 0, critical: 0, high: 0 };
    statements.push({
      sql: `INSERT INTO repo_snapshots (
        id, owner_sub, source, full_name, html_url, description, visibility,
        default_branch, primary_language, languages_json, frameworks_json,
        ecosystems_json, runtimes_json, manifests_json, docker_images_json,
        dependencies_json, key_files_json, findings_count, critical_count,
        high_count, last_pushed_at, scanned_at
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      params: [
        `${ownerSub}:${repo.fullName}`,
        ownerSub,
        repo.source,
        repo.fullName,
        repo.htmlUrl,
        repo.description,
        repo.visibility,
        repo.defaultBranch,
        repo.primaryLanguage,
        JSON.stringify(repo.languages),
        JSON.stringify(repo.frameworks),
        JSON.stringify(repo.ecosystems),
        JSON.stringify(repo.runtimes),
        JSON.stringify(repo.manifests),
        JSON.stringify(repo.dockerImages),
        JSON.stringify(repo.dependencies),
        JSON.stringify(repo.keyFiles),
        counts.total,
        counts.critical,
        counts.high,
        repo.lastPushedAt,
        nowIso,
      ],
    });
  }

  for (const f of findings) {
    const scopedId = `${ownerSub}::${f.id}`;
    const effectiveStatus = statusMap.get(scopedId) ?? f.status;
    statements.push({
      sql: `INSERT INTO vulnerability_findings (
        id, owner_sub, repo_full_name, advisory_id, aliases_json, title,
        summary, severity, category, ecosystem, package_name, installed_version,
        fixed_version, manifest_path, reference_url, status, detected_at
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      params: [
        scopedId,
        ownerSub,
        f.repoFullName,
        f.advisoryId,
        JSON.stringify(f.aliases),
        f.title,
        f.summary,
        f.severity,
        f.category,
        f.ecosystem,
        f.packageName,
        f.installedVersion,
        f.fixedVersion,
        f.manifestPath,
        f.referenceUrl,
        effectiveStatus,
        nowIso,
      ],
    });
  }

  const totalDeps = repos.reduce((sum, r) => sum + r.dependencies.length, 0);
  const runId = crypto.randomUUID();
  statements.push({
    sql: `INSERT INTO scan_runs (
      id, owner_sub, mode, repos_scanned, dependencies_indexed, findings_detected, duration_ms, created_at
    ) VALUES (?,?,?,?,?,?,?,?)`,
    params: [runId, ownerSub, mode, repos.length, totalDeps, findings.length, durationMs, nowIso],
  });

  await dbBatch(statements);

  return {
    id: runId,
    mode,
    reposScanned: repos.length,
    dependenciesIndexed: totalDeps,
    findingsDetected: findings.length,
    durationMs,
    createdAt: nowIso,
  };
}

function seededGitHubFleet(): { repos: RepoSnapshot[]; findings: VulnerabilityFinding[] } | null {
  const repos = fleetSeed.repos as RepoSnapshot[];
  const findings = fleetSeed.findings as VulnerabilityFinding[];
  if (!Array.isArray(repos) || repos.length === 0) return null;
  return { repos, findings };
}

export async function syncFleetForOwner(ownerSub: string): Promise<{
  mode: "github" | "sample";
  scanRun: ScanRunRecord;
}> {
  const started = Date.now();
  const hasToken = isGitHubTokenConfigured();

  if (hasToken) {
    const { repos, findings } = await scanLiveGitHubFleet(ownerSub);
    const scanRun = await persistFleetSnapshot(
      ownerSub,
      "github",
      repos,
      findings,
      Date.now() - started,
    );
    return { mode: "github", scanRun };
  }

  const seeded = seededGitHubFleet();
  if (seeded) {
    const scanRun = await persistFleetSnapshot(
      ownerSub,
      "github",
      seeded.repos,
      seeded.findings,
      Date.now() - started,
    );
    return { mode: "github", scanRun };
  }

  const sampleRepos = buildSampleRepos(ownerSub);
  const sampleFindings = buildSampleFindings();
  const scanRun = await persistFleetSnapshot(
    ownerSub,
    "sample",
    sampleRepos,
    sampleFindings,
    Date.now() - started,
  );
  return { mode: "sample", scanRun };
}

export async function loadFleetDashboard(ownerSub: string): Promise<{
  mode: "github" | "sample";
  githubConfigured: boolean;
  repos: RepoSnapshot[];
  findings: VulnerabilityFinding[];
  advisoryChecks: AdvisoryCheckRun[];
  lastScan: ScanRunRecord | null;
}> {
  const githubConfigured = isGitHubTokenConfigured();
  let repoRows = await dbAll<RepoRow>(
    "SELECT * FROM repo_snapshots WHERE owner_sub = ? ORDER BY critical_count DESC, high_count DESC, full_name ASC",
    [ownerSub],
  );

  const needsInit = githubConfigured && (repoRows.length === 0 || repoRows[0]?.source !== "github");
  if (needsInit) {
    try {
      await syncFleetForOwner(ownerSub);
      repoRows = await dbAll<RepoRow>(
        "SELECT * FROM repo_snapshots WHERE owner_sub = ? ORDER BY critical_count DESC, high_count DESC, full_name ASC",
        [ownerSub],
      );
    } catch {
      // Leave empty if GitHub sync fails
    }
  }

  const findingRows = await dbAll<FindingRow>(
    `SELECT * FROM vulnerability_findings
     WHERE owner_sub = ?
     ORDER BY
       CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
       repo_full_name ASC`,
    [ownerSub],
  );

  const checkRows = await dbAll<AdvisoryCheckRow>(
    "SELECT * FROM advisory_checks WHERE owner_sub = ? ORDER BY created_at DESC LIMIT 25",
    [ownerSub],
  );

  const scanRows = await dbAll<ScanRunRow>(
    "SELECT * FROM scan_runs WHERE owner_sub = ? ORDER BY created_at DESC LIMIT 1",
    [ownerSub],
  );

  const repos = repoRows.map(mapRepoRow);
  const findings = findingRows.map(mapFindingRow);
  const advisoryChecks = checkRows.map(mapAdvisoryCheckRow);
  const lastScan: ScanRunRecord | null = scanRows[0]
    ? {
        id: scanRows[0].id,
        mode: scanRows[0].mode,
        reposScanned: Number(scanRows[0].repos_scanned),
        dependenciesIndexed: Number(scanRows[0].dependencies_indexed),
        findingsDetected: Number(scanRows[0].findings_detected),
        durationMs: Number(scanRows[0].duration_ms),
        createdAt: String(scanRows[0].created_at),
      }
    : null;

  const mode = repos[0]?.source ?? (githubConfigured ? "github" : "sample");

  return {
    mode,
    githubConfigured,
    repos,
    findings,
    advisoryChecks,
    lastScan,
  };
}

export async function runAndSaveAdvisoryCheck(
  ownerSub: string,
  queryInput: string,
  runStage2: boolean,
): Promise<AdvisoryCheckRun> {
  const dashboard = await loadFleetDashboard(ownerSub);
  const parsed = await parseAdvisoryInput(queryInput);
  const results = await evaluateAdvisoryAgainstFleet(parsed, dashboard.repos, runStage2);

  const affectedCount = results.filter((r) => r.verdict === "affected").length;
  const needsReviewCount = results.filter((r) => r.verdict === "needs_review").length;
  const clearedCount = results.filter((r) => r.verdict === "cleared").length;

  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  await dbRun(
    `INSERT INTO advisory_checks (
      id, owner_sub, query_input, parsed_summary, parsed_json,
      total_repos, affected_count, needs_review_count, cleared_count,
      results_json, created_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    [
      id,
      ownerSub,
      queryInput,
      parsed.summary,
      JSON.stringify(parsed),
      results.length,
      affectedCount,
      needsReviewCount,
      clearedCount,
      JSON.stringify(results),
      createdAt,
    ],
  );

  return {
    id,
    queryInput,
    parsedSummary: parsed.summary,
    parsed,
    totalRepos: results.length,
    affectedCount,
    needsReviewCount,
    clearedCount,
    results,
    createdAt,
  };
}

export async function updateFindingStatus(
  ownerSub: string,
  findingId: string,
  status: FindingStatus,
): Promise<boolean> {
  const existing = await dbAll<{ id: string; repo_full_name: string }>(
    "SELECT id, repo_full_name FROM vulnerability_findings WHERE id = ? AND owner_sub = ?",
    [findingId, ownerSub],
  );
  if (existing.length === 0) return false;

  await dbRun(
    "UPDATE vulnerability_findings SET status = ? WHERE id = ? AND owner_sub = ?",
    [status, findingId, ownerSub],
  );

  const repoName = existing[0].repo_full_name;
  const activeCounts = await dbAll<{ severity: Severity }>(
    `SELECT severity FROM vulnerability_findings
     WHERE owner_sub = ? AND repo_full_name = ? AND status != 'dismissed'`,
    [ownerSub, repoName],
  );

  const total = activeCounts.length;
  const critical = activeCounts.filter((r) => r.severity === "CRITICAL").length;
  const high = activeCounts.filter((r) => r.severity === "HIGH").length;

  await dbRun(
    `UPDATE repo_snapshots
     SET findings_count = ?, critical_count = ?, high_count = ?
     WHERE owner_sub = ? AND full_name = ?`,
    [total, critical, high, ownerSub, repoName],
  );

  return true;
}

export async function deleteAdvisoryCheck(ownerSub: string, checkId: string): Promise<boolean> {
  const existing = await dbAll<{ id: string }>(
    "SELECT id FROM advisory_checks WHERE id = ? AND owner_sub = ?",
    [checkId, ownerSub],
  );
  if (existing.length === 0) return false;

  await dbRun("DELETE FROM advisory_checks WHERE id = ? AND owner_sub = ?", [
    checkId,
    ownerSub,
  ]);
  return true;
}
