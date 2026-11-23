"use client";

import { useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Code2,
  ExternalLink,
  FileCode2,
  Layers,
  Loader2,
  Radar,
  Search,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { SeverityBadge, VerdictBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import type { AdvisoryCheckRun, RepoAdvisoryVerdict, VerdictStatus } from "@/lib/types";

const PRESET_ADVISORIES = [
  {
    label: "New PHP CGI flaw (CVE-2024-4577)",
    query: "New PHP-CGI argument injection vulnerability CVE-2024-4577 — check if any repo runs PHP or PHP-CGI",
  },
  {
    label: "Next.js middleware bypass (CVE-2025-29927)",
    query: "CVE-2025-29927 Next.js middleware authorization bypass via x-middleware-subrequest",
  },
  {
    label: "Axios SSRF / header leak",
    query: "CVE-2025-27152 Axios SSRF and credential leak when passing absolute URLs",
  },
  {
    label: "FastAPI / Starlette DoS",
    query: "CVE-2024-47874 Starlette and FastAPI multipart form denial of service",
  },
  {
    label: "Docker Alpine OpenSSL",
    query: "New OpenSSL vulnerability affecting Docker Alpine Linux base images",
  },
];

interface AdvisoryCheckerProps {
  totalRepos: number;
  activeCheck: AdvisoryCheckRun | null;
  onCheckCompleted: (check: AdvisoryCheckRun) => void;
}

export function AdvisoryChecker({
  totalRepos,
  activeCheck,
  onCheckCompleted,
}: AdvisoryCheckerProps) {
  const [query, setQuery] = useState("");
  const [runStage2, setRunStage2] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<"all" | VerdictStatus>("all");
  const [expandedRepos, setExpandedRepos] = useState<Record<string, boolean>>({});

  async function executeCheck(customQuery?: string) {
    const text = (customQuery ?? query).trim();
    if (!text) return;
    if (customQuery) setQuery(customQuery);
    setRunning(true);
    setError(null);
    setVerdictFilter("all");

    try {
      const res = await fetch("/api/advisory-check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: text, runStage2 }),
      });
      const data = (await res.json()) as { check?: AdvisoryCheckRun; error?: string };
      if (!res.ok || !data.check) {
        setError(data.error ?? "Unable to run advisory check.");
        return;
      }

      // Auto-expand affected & needs_review repos for immediate clarity
      const nextExpanded: Record<string, boolean> = {};
      for (const r of data.check.results) {
        if (r.verdict !== "cleared") {
          nextExpanded[r.repoFullName] = true;
        }
      }
      setExpandedRepos(nextExpanded);
      onCheckCompleted(data.check);
    } catch {
      setError("Network error while running advisory check.");
    } finally {
      setRunning(false);
    }
  }

  function toggleExpand(repoName: string) {
    setExpandedRepos((prev) => ({ ...prev, [repoName]: !prev[repoName] }));
  }

  const filteredVerdicts: RepoAdvisoryVerdict[] = activeCheck
    ? activeCheck.results.filter((r) => verdictFilter === "all" || r.verdict === verdictFilter)
    : [];

  return (
    <Card className="border-border/80 shadow-sm">
      <CardHeader className="pb-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <Radar className="size-4.5" />
            </div>
            <div>
              <CardTitle className="text-lg">Fleet Advisory Check</CardTitle>
              <CardDescription>
                Paste a CVE, advisory URL, or describe a breaking security flaw to check all{" "}
                {totalRepos} indexed repositories in two stages.
              </CardDescription>
            </div>
          </div>
          <Badge variant="outline" className="w-fit gap-1.5 text-xs">
            <Layers className="size-3" />
            Stage 1 SBOM Filter + Stage 2 Code Triage
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void executeCheck();
          }}
          className="space-y-3"
        >
          <Textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="e.g. 'New PHP-CGI vulnerability CVE-2024-4577' or 'CVE-2025-29927' or paste an advisory URL..."
            rows={2}
            className="min-h-16 resize-none bg-background text-sm"
            disabled={running}
          />

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground select-none">
              <input
                type="checkbox"
                checked={runStage2}
                onChange={(e) => setRunStage2(e.target.checked)}
                className="size-3.5 rounded border-input accent-primary"
                disabled={running}
              />
              <span>
                Run Stage 2 targeted code, config &amp; runtime reachability triage on candidate repos
              </span>
            </label>

            <Button type="submit" disabled={running || query.trim().length < 2} className="gap-2">
              {running ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  Checking Fleet...
                </>
              ) : (
                <>
                  <Search className="size-4" />
                  Check All {totalRepos} Repos
                </>
              )}
            </Button>
          </div>
        </form>

        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-xs font-medium text-muted-foreground">Try an advisory:</span>
          {PRESET_ADVISORIES.map((preset) => (
            <button
              key={preset.label}
              type="button"
              disabled={running}
              onClick={() => void executeCheck(preset.query)}
              className="inline-flex items-center gap-1 rounded-full border border-border bg-muted/50 px-2.5 py-1 text-xs text-foreground transition-colors hover:bg-muted disabled:opacity-50"
            >
              <Sparkles className="size-3 text-muted-foreground" />
              {preset.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            <AlertOctagon className="size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {activeCheck && (
          <div className="mt-4 space-y-4 rounded-xl border border-border bg-muted/20 p-4">
            <div className="flex flex-col gap-3 border-b border-border pb-4 md:flex-row md:items-start md:justify-between">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={activeCheck.parsed.severity} />
                  <h3 className="text-sm font-semibold text-foreground">
                    {activeCheck.parsed.title}
                  </h3>
                  <Badge variant="secondary" className="text-[11px]">
                    {activeCheck.parsed.source === "osv"
                      ? "OSV.dev Verified"
                      : activeCheck.parsed.source === "curated"
                        ? "Curated Intel"
                        : "Heuristic Parser"}
                  </Badge>
                </div>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {activeCheck.parsed.summary}
                </p>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {activeCheck.parsed.cveIds.map((id) => (
                    <Badge key={id} variant="outline" className="font-mono text-[11px]">
                      {id}
                    </Badge>
                  ))}
                  {activeCheck.parsed.ecosystems.map((eco) => (
                    <Badge key={eco} variant="secondary" className="text-[11px]">
                      Ecosystem: {eco}
                    </Badge>
                  ))}
                  {activeCheck.parsed.languages.map((lang) => (
                    <Badge key={lang} variant="secondary" className="text-[11px]">
                      Lang: {lang}
                    </Badge>
                  ))}
                  {activeCheck.parsed.packages.map((pkg) => (
                    <Badge key={pkg.name} variant="outline" className="font-mono text-[11px]">
                      pkg:{pkg.name}
                      {pkg.fixedVersion ? ` (fix ${pkg.fixedVersion})` : ""}
                    </Badge>
                  ))}
                </div>
              </div>

              {activeCheck.parsed.referenceUrl && (
                <a
                  href={activeCheck.parsed.referenceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-primary underline-offset-4 hover:underline"
                >
                  Advisory Source
                  <ExternalLink className="size-3" />
                </a>
              )}
            </div>

            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <button
                type="button"
                onClick={() => setVerdictFilter("all")}
                className={`flex items-center justify-between rounded-lg border px-3 py-2 text-left transition-colors ${
                  verdictFilter === "all"
                    ? "border-primary bg-background shadow-xs"
                    : "border-border bg-background/60 hover:bg-background"
                }`}
              >
                <span className="text-xs font-medium text-muted-foreground">All Repos</span>
                <span className="text-base font-semibold">{activeCheck.totalRepos}</span>
              </button>

              <button
                type="button"
                onClick={() => setVerdictFilter("affected")}
                className={`flex items-center justify-between rounded-lg border px-3 py-2 text-left transition-colors ${
                  verdictFilter === "affected"
                    ? "border-red-500 bg-red-500/10"
                    : "border-border bg-background/60 hover:bg-background"
                }`}
              >
                <span className="flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-300">
                  <AlertOctagon className="size-3.5" />
                  Affected
                </span>
                <span className="text-base font-semibold text-red-700 dark:text-red-300">
                  {activeCheck.affectedCount}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setVerdictFilter("needs_review")}
                className={`flex items-center justify-between rounded-lg border px-3 py-2 text-left transition-colors ${
                  verdictFilter === "needs_review"
                    ? "border-amber-500 bg-amber-500/10"
                    : "border-border bg-background/60 hover:bg-background"
                }`}
              >
                <span className="flex items-center gap-1.5 text-xs font-medium text-amber-800 dark:text-amber-300">
                  <AlertTriangle className="size-3.5" />
                  Needs Check
                </span>
                <span className="text-base font-semibold text-amber-800 dark:text-amber-300">
                  {activeCheck.needsReviewCount}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setVerdictFilter("cleared")}
                className={`flex items-center justify-between rounded-lg border px-3 py-2 text-left transition-colors ${
                  verdictFilter === "cleared"
                    ? "border-emerald-500 bg-emerald-500/10"
                    : "border-border bg-background/60 hover:bg-background"
                }`}
              >
                <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-300">
                  <CheckCircle2 className="size-3.5" />
                  Cleared
                </span>
                <span className="text-base font-semibold text-emerald-700 dark:text-emerald-300">
                  {activeCheck.clearedCount}
                </span>
              </button>
            </div>

            <div className="space-y-2">
              {filteredVerdicts.length === 0 ? (
                <div className="flex items-center justify-center gap-2 rounded-lg border border-dashed border-border py-8 text-xs text-muted-foreground">
                  <ShieldCheck className="size-4" />
                  No repositories in this verdict bucket.
                </div>
              ) : (
                filteredVerdicts.map((item) => {
                  const isOpen = Boolean(expandedRepos[item.repoFullName]);
                  return (
                    <div
                      key={item.repoFullName}
                      className="overflow-hidden rounded-lg border border-border bg-background"
                    >
                      <button
                        type="button"
                        onClick={() => toggleExpand(item.repoFullName)}
                        className="flex w-full items-start justify-between gap-3 px-3.5 py-3 text-left transition-colors hover:bg-muted/40"
                      >
                        <div className="flex min-w-0 items-start gap-2.5">
                          {isOpen ? (
                            <ChevronDown className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                          )}
                          <div className="min-w-0 space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-mono text-xs font-semibold text-foreground sm:text-sm">
                                {item.repoFullName}
                              </span>
                              <Badge variant="secondary" className="text-[11px]">
                                {item.primaryLanguage}
                              </Badge>
                              {item.frameworks.slice(0, 2).map((fw) => (
                                <Badge key={fw} variant="outline" className="text-[11px]">
                                  {fw}
                                </Badge>
                              ))}
                            </div>
                            <p className="text-xs text-muted-foreground">{item.stage1Reason}</p>
                          </div>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <VerdictBadge verdict={item.verdict} />
                        </div>
                      </button>

                      {isOpen && (
                        <div className="space-y-3 border-t border-border bg-muted/20 px-4 py-3 text-xs">
                          <div className="grid gap-3 md:grid-cols-2">
                            <div className="space-y-1.5">
                              <div className="font-semibold text-foreground">
                                Stage 1 — Deterministic Stack &amp; SBOM Filter
                              </div>
                              <p className="text-muted-foreground">{item.stage1Reason}</p>
                              {item.matchedPackages.length > 0 && (
                                <div className="flex flex-wrap gap-1.5 pt-1">
                                  {item.matchedPackages.map((pkg) => (
                                    <Badge
                                      key={`${pkg.ecosystem}:${pkg.name}`}
                                      variant="outline"
                                      className="font-mono text-[11px]"
                                    >
                                      {pkg.name}@{pkg.installedVersion}
                                      {pkg.fixedVersion ? ` → fix ${pkg.fixedVersion}` : ""}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                            </div>

                            <div className="space-y-1.5">
                              <div className="flex items-center gap-2 font-semibold text-foreground">
                                <span>Stage 2 — Targeted Code &amp; Runtime Triage</span>
                                <Badge variant="secondary" className="text-[10px]">
                                  {item.stage2.mode === "live_github"
                                    ? "Live Code Search"
                                    : item.stage2.mode === "indexed_heuristic"
                                      ? "Indexed Inspection"
                                      : "Skipped"}
                                </Badge>
                              </div>
                              <ul className="space-y-1 text-muted-foreground">
                                {item.stage2.notes.map((note, idx) => (
                                  <li key={idx}>• {note}</li>
                                ))}
                              </ul>
                              {item.stage2.matchedFiles.length > 0 && (
                                <div className="flex flex-wrap gap-1.5 pt-1">
                                  {item.stage2.matchedFiles.map((f) => (
                                    <span
                                      key={f}
                                      className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                                    >
                                      <FileCode2 className="size-3" />
                                      {f}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>

                          {item.stage2.codeHits.length > 0 && (
                            <div className="space-y-1.5">
                              <div className="flex items-center gap-1.5 font-semibold text-foreground">
                                <Code2 className="size-3.5" />
                                Code &amp; Config Evidence
                              </div>
                              <div className="space-y-1.5">
                                {item.stage2.codeHits.map((hit, i) => (
                                  <div
                                    key={`${hit.path}-${i}`}
                                    className="rounded-md border border-border bg-background p-2 font-mono text-[11px]"
                                  >
                                    <div className="mb-1 flex items-center justify-between text-muted-foreground">
                                      <span>{hit.path}</span>
                                      <Badge variant="outline" className="text-[10px]">
                                        match: {hit.pattern}
                                      </Badge>
                                    </div>
                                    <pre className="overflow-x-auto whitespace-pre-wrap text-foreground">
                                      {hit.snippet}
                                    </pre>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          <div className="flex flex-col gap-2 rounded-md border border-border bg-background px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                              <span className="font-semibold text-foreground">Remediation: </span>
                              <span className="text-muted-foreground">{item.remediation}</span>
                            </div>
                            {item.htmlUrl && (
                              <a
                                href={item.htmlUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex shrink-0 items-center gap-1 font-medium text-primary hover:underline"
                              >
                                Open Repo
                                <ExternalLink className="size-3" />
                              </a>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
