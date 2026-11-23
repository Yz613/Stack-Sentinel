export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type FindingCategory = "dependency" | "runtime" | "config";
export type FindingStatus = "open" | "acknowledged" | "dismissed";
export type VerdictStatus = "affected" | "needs_review" | "cleared";

export interface DependencyItem {
  name: string;
  version: string;
  ecosystem: string;
  manifestPath: string;
  direct?: boolean;
}

export interface RuntimeSignal {
  runtime: string;
  version: string;
  pinned: boolean;
  sourceFile: string;
}

export interface RepoSnapshot {
  id: string;
  source: "github" | "sample";
  fullName: string;
  htmlUrl: string;
  description: string;
  visibility: string;
  defaultBranch: string;
  primaryLanguage: string;
  languages: string[];
  frameworks: string[];
  ecosystems: string[];
  runtimes: RuntimeSignal[];
  manifests: string[];
  dockerImages: string[];
  dependencies: DependencyItem[];
  keyFiles: string[];
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  lastPushedAt: string | null;
  scannedAt: string;
}

export interface VulnerabilityFinding {
  id: string;
  repoFullName: string;
  advisoryId: string;
  aliases: string[];
  title: string;
  summary: string;
  severity: Severity;
  category: FindingCategory;
  ecosystem: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string;
  manifestPath: string;
  referenceUrl: string;
  status: FindingStatus;
  detectedAt: string;
}

export interface ParsedAdvisory {
  title: string;
  summary: string;
  cveIds: string[];
  ecosystems: string[];
  languages: string[];
  packages: {
    name: string;
    ecosystem?: string;
    affectedBelow?: string;
    fixedVersion?: string;
  }[];
  frameworks: string[];
  dockerKeywords: string[];
  runtimeTargets: string[];
  configFiles: string[];
  codePatterns: string[];
  severity: Severity;
  source: "osv" | "curated" | "heuristic";
  referenceUrl?: string;
}

export interface Stage2Evidence {
  executed: boolean;
  mode: "live_github" | "indexed_heuristic" | "skipped";
  reachability: "confirmed" | "likely" | "unverified_runtime" | "not_applicable";
  matchedFiles: string[];
  codeHits: { path: string; snippet: string; pattern: string }[];
  notes: string[];
}

export interface RepoAdvisoryVerdict {
  repoFullName: string;
  htmlUrl: string;
  primaryLanguage: string;
  frameworks: string[];
  verdict: VerdictStatus;
  confidence: "high" | "medium" | "low";
  stage1Outcome: "cleared" | "candidate" | "direct_match";
  stage1Reason: string;
  matchedPackages: {
    name: string;
    installedVersion: string;
    fixedVersion?: string;
    ecosystem: string;
    manifestPath: string;
  }[];
  stage2: Stage2Evidence;
  remediation: string;
}

export interface AdvisoryCheckRun {
  id: string;
  queryInput: string;
  parsedSummary: string;
  parsed: ParsedAdvisory;
  totalRepos: number;
  affectedCount: number;
  needsReviewCount: number;
  clearedCount: number;
  results: RepoAdvisoryVerdict[];
  createdAt: string;
}

export interface ScanRunRecord {
  id: string;
  mode: "github" | "sample";
  reposScanned: number;
  dependenciesIndexed: number;
  findingsDetected: number;
  durationMs: number;
  createdAt: string;
}

export interface FleetDashboardPayload {
  mode: "github" | "sample";
  githubConfigured: boolean;
  viewer: {
    name: string;
    email: string;
    authMode: "cloudflare_access" | "access_key" | "open";
  };
  repos: RepoSnapshot[];
  findings: VulnerabilityFinding[];
  advisoryChecks: AdvisoryCheckRun[];
  lastScan: ScanRunRecord | null;
}
