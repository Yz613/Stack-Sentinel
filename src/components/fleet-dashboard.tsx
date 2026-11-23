"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertOctagon,
  CheckCircle2,
  ChevronDown,
  ExternalLink,
  KeyRound,
  Loader2,
  LogOut,
  RefreshCw,
  Shield,
  ShieldCheck,
} from "lucide-react";
import { CopyPromptButton } from "@/components/copy-prompt-button";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { RepoSnapshot, Severity, VulnerabilityFinding } from "@/lib/types";

const STORAGE_TOKEN_KEY = "stack_sentinel_gh_token";
const STORAGE_SCAN_KEY = "stack_sentinel_scan_v1";
const STORAGE_DISMISSED_KEY = "stack_sentinel_dismissed_v1";

interface LocalScanState {
  user: { login: string; avatarUrl: string };
  repos: RepoSnapshot[];
  findings: VulnerabilityFinding[];
  scannedAt: string;
  threatWatch?: {
    checkedAt: string;
    feedItemsChecked: number;
    matchedCount: number;
    summary: string;
  };
}

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

function formatTime(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function buildRepoFixPrompt(
  repoFullName: string,
  defaultBranch: string,
  findings: VulnerabilityFinding[],
): string {
  if (findings.length === 1) {
    const f = findings[0];
    const location = f.manifestPath || "the dependency manifest";
    const fixAction = f.fixedVersion
      ? `Update \`${f.packageName}\` (${f.ecosystem}) from \`${f.installedVersion}\` to \`${f.fixedVersion}\` (or newer) in \`${location}\` and regenerate the lockfile.`
      : `Review \`${f.packageName}\` (${f.ecosystem} \`${f.installedVersion}\`) in \`${location}\` and apply the vendor mitigation or remove the affected package.`;

    return [
      `Fix ${f.severity} vulnerability ${f.advisoryId} in ${repoFullName} (branch: ${defaultBranch}).`,
      ``,
      `Issue: ${f.packageName}@${f.installedVersion} in ${location} — ${f.title}.`,
      f.summary ? `Details: ${f.summary}` : "",
      `Fix: ${fixAction}`,
      f.referenceUrl ? `Reference: ${f.referenceUrl}` : "",
      ``,
      `Run install, lint/typecheck, and build/tests to verify, then summarize the changes.`,
    ]
      .filter(Boolean)
      .join("\n");
  }

  const items = findings.map((f, idx) => {
    const location = f.manifestPath || "the dependency manifest";
    const action = f.fixedVersion
      ? `Update \`${f.packageName}\` (${f.ecosystem}) from \`${f.installedVersion}\` to \`${f.fixedVersion}\` in \`${location}\``
      : `Review/mitigate \`${f.packageName}\` (${f.ecosystem} \`${f.installedVersion}\`) in \`${location}\``;

    return [
      `${idx + 1}. [${f.severity}] ${f.advisoryId} — ${f.title}`,
      `   - Fix: ${action}`,
      f.summary ? `   - Details: ${f.summary}` : "",
      f.referenceUrl ? `   - Reference: ${f.referenceUrl}` : "",
    ]
      .filter(Boolean)
      .join("\n");
  });

  return [
    `Fix ${findings.length} security vulnerabilities in ${repoFullName} (branch: ${defaultBranch}).`,
    ``,
    ...items,
    ``,
    `After applying all updates and regenerating lockfiles, run install, lint/typecheck, and build/tests to verify, then summarize the changes.`,
  ].join("\n");
}

export function FleetDashboard() {
  const [hydrated, setHydrated] = useState(false);
  const [token, setToken] = useState("");
  const [tokenInput, setTokenInput] = useState("");
  const [scanState, setScanState] = useState<LocalScanState | null>(null);
  const [dismissedIds, setDismissedIds] = useState<string[]>([]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void Promise.resolve().then(() => {
      if (!active) return;
      try {
        const savedToken = localStorage.getItem(STORAGE_TOKEN_KEY) ?? "";
        const savedScan = localStorage.getItem(STORAGE_SCAN_KEY);
        const savedDismissed = localStorage.getItem(STORAGE_DISMISSED_KEY);
        if (savedToken) setToken(savedToken);
        if (savedScan) setScanState(JSON.parse(savedScan) as LocalScanState);
        if (savedDismissed) setDismissedIds(JSON.parse(savedDismissed) as string[]);
      } catch {
        // Ignore corrupted localStorage
      } finally {
        if (active) setHydrated(true);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  async function runPrivateScan(activeToken: string) {
    setScanning(true);
    setError(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-github-token": activeToken.trim(),
        },
        body: "{}",
      });
      const json = (await res.json()) as LocalScanState & { error?: string };
      if (!res.ok) {
        setError(json.error ?? "Scan failed. Please verify your GitHub token.");
        return false;
      }

      const nextState: LocalScanState = {
        user: json.user,
        repos: json.repos,
        findings: json.findings,
        scannedAt: json.scannedAt,
        threatWatch: json.threatWatch,
      };
      setScanState(nextState);
      localStorage.setItem(STORAGE_TOKEN_KEY, activeToken.trim());
      localStorage.setItem(STORAGE_SCAN_KEY, JSON.stringify(nextState));
      setToken(activeToken.trim());
      return true;
    } catch {
      setError("Network error while scanning repositories.");
      return false;
    } finally {
      setScanning(false);
    }
  }

  async function handleConnect(e: React.FormEvent) {
    e.preventDefault();
    const candidate = tokenInput.trim();
    if (!candidate) return;
    const ok = await runPrivateScan(candidate);
    if (ok) setTokenInput("");
  }

  function handleDisconnect() {
    localStorage.removeItem(STORAGE_TOKEN_KEY);
    localStorage.removeItem(STORAGE_SCAN_KEY);
    localStorage.removeItem(STORAGE_DISMISSED_KEY);
    setToken("");
    setTokenInput("");
    setScanState(null);
    setDismissedIds([]);
    setError(null);
  }

  function handleDismiss(id: string) {
    const next = dismissedIds.includes(id) ? dismissedIds : [...dismissedIds, id];
    setDismissedIds(next);
    localStorage.setItem(STORAGE_DISMISSED_KEY, JSON.stringify(next));
  }

  function handleRestore(id: string) {
    const next = dismissedIds.filter((item) => item !== id);
    setDismissedIds(next);
    localStorage.setItem(STORAGE_DISMISSED_KEY, JSON.stringify(next));
  }

  const repoByName = useMemo(() => {
    const map = new Map<string, { htmlUrl: string; defaultBranch: string }>();
    for (const r of scanState?.repos ?? []) {
      map.set(r.fullName, { htmlUrl: r.htmlUrl, defaultBranch: r.defaultBranch });
    }
    return map;
  }, [scanState?.repos]);

  const dismissedSet = useMemo(() => new Set(dismissedIds), [dismissedIds]);

  const openIssues = useMemo(() => {
    return (scanState?.findings ?? []).filter((f) => !dismissedSet.has(f.id));
  }, [scanState?.findings, dismissedSet]);

  const dismissedIssues = useMemo(() => {
    return (scanState?.findings ?? []).filter((f) => dismissedSet.has(f.id));
  }, [scanState?.findings, dismissedSet]);

  const reposWithIssues = useMemo(() => {
    const groups = new Map<string, VulnerabilityFinding[]>();
    for (const issue of openIssues) {
      const existing = groups.get(issue.repoFullName);
      if (existing) {
        existing.push(issue);
      } else {
        groups.set(issue.repoFullName, [issue]);
      }
    }
    return Array.from(groups.entries())
      .map(([repoFullName, issues]) => {
        const sorted = [...issues].sort(
          (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
        );
        return {
          repoFullName,
          highestSeverity: sorted[0].severity,
          issues: sorted,
        };
      })
      .sort(
        (a, b) =>
          SEVERITY_RANK[a.highestSeverity] - SEVERITY_RANK[b.highestSeverity] ||
          b.issues.length - a.issues.length,
      );
  }, [openIssues]);

  if (!hydrated) {
    return <div className="min-h-screen bg-background" />;
  }

  if (!token) {
    return (
      <div className="min-h-screen bg-background">
        <header className="border-b border-border/80 bg-background/90">
          <div className="mx-auto flex max-w-3xl items-center gap-2.5 px-4 py-3 sm:px-6">
            <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <Shield className="size-4" />
            </div>
            <h1 className="text-base font-semibold tracking-tight">StackSentinel</h1>
          </div>
        </header>

        <main className="mx-auto flex max-w-md flex-col justify-center px-4 py-16 sm:px-6">
          <Card className="border-border/80 shadow-sm">
            <CardHeader className="space-y-2">
              <div className="flex size-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
                <KeyRound className="size-5" />
              </div>
              <CardTitle className="text-lg">Connect Your GitHub</CardTitle>
              <CardDescription className="text-xs leading-relaxed">
                Scan your own repositories against OSV.dev and{" "}
                <a
                  href="https://helix.ml/threat-watch?range=2026&chart=line"
                  target="_blank"
                  rel="noreferrer"
                  className="underline underline-offset-2 hover:text-foreground"
                >
                  Helix Threat Watch
                </a>
                . Everything stays strictly in your browser—no tokens or repos are stored on our
                servers.
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
              <form onSubmit={(e) => void handleConnect(e)} className="space-y-3">
                <Input
                  type="password"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder="Paste GitHub Personal Access Token (ghp_...)"
                  autoComplete="off"
                  disabled={scanning}
                />
                {error && (
                  <p className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                    {error}
                  </p>
                )}
                <Button
                  type="submit"
                  className="w-full gap-1.5"
                  disabled={scanning || !tokenInput.trim()}
                >
                  {scanning ? (
                    <>
                      <Loader2 className="size-4 animate-spin" />
                      Scanning your repositories...
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="size-4" />
                      Connect &amp; Scan My Repos
                    </>
                  )}
                </Button>
              </form>

              <div className="space-y-1.5 rounded-lg bg-muted/40 p-3 text-[11px] text-muted-foreground">
                <p className="font-medium text-foreground">Need a token?</p>
                <p>
                  Create a classic token with <code className="font-mono">repo</code> (or{" "}
                  <code className="font-mono">public_repo</code> for public repos only):{" "}
                  <a
                    href="https://github.com/settings/tokens/new?scopes=repo&description=StackSentinel"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-0.5 text-primary underline underline-offset-2"
                  >
                    Create GitHub Token
                    <ExternalLink className="size-3" />
                  </a>
                </p>
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Simple single-row header */}
      <header className="sticky top-0 z-30 border-b border-border/80 bg-background/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-3xl items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <Shield className="size-4" />
            </div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-semibold tracking-tight">StackSentinel</h1>
              {scanState?.user.login && (
                <Badge variant="secondary" className="text-[11px] font-normal">
                  @{scanState.user.login}
                </Badge>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              onClick={() => void runPrivateScan(token)}
              disabled={scanning}
              className="gap-1.5"
            >
              {scanning ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <RefreshCw className="size-3.5" />
              )}
              {scanning ? "Scanning..." : "Scan Now"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={handleDisconnect}
              disabled={scanning}
              title="Disconnect GitHub & clear browser data"
              aria-label="Disconnect GitHub"
              className="gap-1 text-muted-foreground hover:text-foreground"
            >
              <LogOut className="size-3.5" />
              <span className="hidden sm:inline">Disconnect</span>
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-3xl space-y-6 px-4 py-6 sm:px-6">
        {error && (
          <div className="flex items-center justify-between gap-3 rounded-xl border border-destructive/40 bg-destructive/10 px-4 py-3 text-xs text-destructive">
            <div className="flex items-center gap-2">
              <AlertOctagon className="size-4 shrink-0" />
              <span>{error}</span>
            </div>
            <Button size="xs" variant="ghost" onClick={() => setError(null)}>
              Dismiss
            </Button>
          </div>
        )}

        {scanState && (
          <>
            {/* Compact Status Bar */}
            <section
              aria-label="Scan status"
              className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border/80 bg-card px-4 py-3 text-xs shadow-xs"
            >
              <div className="flex flex-wrap items-center gap-2">
                <CheckCircle2
                  className={`size-4 shrink-0 ${
                    openIssues.length === 0 ? "text-emerald-500" : "text-amber-500"
                  }`}
                />
                <span className="text-sm font-medium text-foreground">
                  {openIssues.length === 0
                    ? "All checks passed"
                    : `${openIssues.length} open ${openIssues.length === 1 ? "issue" : "issues"}`}
                </span>
                <span className="text-muted-foreground">
                  · {scanState.repos.length} repos · Scanned {formatTime(scanState.scannedAt)}
                </span>
              </div>

              {scanState.threatWatch && (
                <a
                  href="https://helix.ml/threat-watch?range=2026&chart=line"
                  target="_blank"
                  rel="noreferrer"
                  className="text-muted-foreground underline underline-offset-2 hover:text-foreground"
                >
                  {scanState.threatWatch.summary}
                </a>
              )}
            </section>

            {/* Issues Grouped by Repo (1 clean card per affected repo) */}
            <section aria-label="Issues" className="space-y-4">
              {reposWithIssues.length === 0 ? (
                <Card className="border-border/80 shadow-xs">
                  <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                    <CheckCircle2 className="mb-2.5 size-8 text-emerald-500" />
                    <p className="text-sm font-semibold">Everything looks clean</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      0 open vulnerabilities across your {scanState.repos.length} repositories.
                    </p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-4">
                  {reposWithIssues.map((group) => {
                    const repoMeta = repoByName.get(group.repoFullName);
                    const promptId = `repo-prompt-${group.repoFullName.replace(/[^a-zA-Z0-9_-]/g, "-")}`;
                    const repoPrompt = buildRepoFixPrompt(
                      group.repoFullName,
                      repoMeta?.defaultBranch ?? "main",
                      group.issues,
                    );

                    return (
                      <Card key={group.repoFullName} className="border-border/80 shadow-xs">
                        <CardHeader className="pb-3">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-2">
                              <SeverityBadge severity={group.highestSeverity} />
                              {repoMeta?.htmlUrl ? (
                                <a
                                  href={repoMeta.htmlUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="inline-flex items-center gap-1 text-sm font-semibold hover:underline"
                                >
                                  {group.repoFullName}
                                  <ExternalLink className="size-3 text-muted-foreground" />
                                </a>
                              ) : (
                                <span className="text-sm font-semibold">{group.repoFullName}</span>
                              )}
                              {group.issues.length > 1 && (
                                <Badge variant="secondary" className="text-[11px] font-normal">
                                  {group.issues.length} issues
                                </Badge>
                              )}
                            </div>

                            <CopyPromptButton
                              targetId={promptId}
                              label={
                                group.issues.length > 1
                                  ? `Copy Master Prompt (${group.issues.length})`
                                  : "Copy Fix Prompt"
                              }
                              ariaLabel={`Copy fix prompt for ${group.repoFullName}`}
                            />
                          </div>
                        </CardHeader>

                        <CardContent className="space-y-3 pt-0">
                          <ul className="divide-y divide-border/60 rounded-lg border border-border/60 bg-muted/20">
                            {group.issues.map((issue) => (
                              <li
                                key={issue.id}
                                className="flex flex-col gap-1.5 px-3.5 py-3 text-xs sm:flex-row sm:items-start sm:justify-between"
                              >
                                <div className="space-y-1">
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    <SeverityBadge severity={issue.severity} />
                                    <span className="font-semibold text-foreground">
                                      {issue.packageName}@{issue.installedVersion}
                                    </span>
                                    {issue.fixedVersion && (
                                      <span className="text-emerald-600 dark:text-emerald-400">
                                        → update to {issue.fixedVersion}
                                      </span>
                                    )}
                                    {issue.manifestPath && (
                                      <span className="font-mono text-[11px] text-muted-foreground">
                                        ({issue.manifestPath})
                                      </span>
                                    )}
                                  </div>

                                  <p className="text-foreground">
                                    <span className="font-mono text-[11px] text-muted-foreground">
                                      {issue.advisoryId}
                                    </span>{" "}
                                    — {issue.title}
                                  </p>
                                  {issue.summary && (
                                    <p className="line-clamp-2 text-muted-foreground">
                                      {issue.summary}
                                    </p>
                                  )}
                                </div>

                                <div className="flex shrink-0 items-center gap-2 pt-0.5">
                                  {issue.referenceUrl && (
                                    <a
                                      href={issue.referenceUrl}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-[11px] text-muted-foreground underline underline-offset-2 hover:text-foreground"
                                    >
                                      Advisory
                                    </a>
                                  )}
                                  <Button
                                    size="xs"
                                    variant="ghost"
                                    className="h-6 px-2 text-[11px] text-muted-foreground hover:text-foreground"
                                    onClick={() => handleDismiss(issue.id)}
                                  >
                                    Dismiss
                                  </Button>
                                </div>
                              </li>
                            ))}
                          </ul>

                          <details className="text-xs">
                            <summary className="flex cursor-pointer list-none items-center gap-1 text-muted-foreground hover:text-foreground">
                              <ChevronDown className="size-3.5" />
                              <span>
                                {group.issues.length > 1
                                  ? "Preview master agent prompt"
                                  : "Preview agent prompt"}
                              </span>
                            </summary>
                            <pre
                              id={promptId}
                              className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-lg border border-border/60 bg-muted/40 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground"
                            >
                              {repoPrompt}
                            </pre>
                          </details>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}

              {dismissedIssues.length > 0 && (
                <details className="pt-2 text-xs text-muted-foreground">
                  <summary className="cursor-pointer hover:text-foreground">
                    Dismissed issues ({dismissedIssues.length})
                  </summary>
                  <div className="mt-2 space-y-1.5">
                    {dismissedIssues.map((issue) => (
                      <div
                        key={issue.id}
                        className="flex items-center justify-between gap-2 rounded-lg bg-muted/40 px-3 py-1.5"
                      >
                        <span>
                          <span className="font-medium text-foreground">{issue.repoFullName}</span> ·{" "}
                          <span className="font-mono">{issue.advisoryId}</span> · {issue.packageName}
                        </span>
                        <Button
                          size="xs"
                          variant="ghost"
                          onClick={() => handleRestore(issue.id)}
                        >
                          Restore
                        </Button>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  );
}
