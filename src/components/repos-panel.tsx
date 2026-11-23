"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Box,
  Container,
  ExternalLink,
  FileCode2,
  FolderGit2,
  Lock,
  Package,
  Search,
  Unlock,
} from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { RepoSnapshot, VulnerabilityFinding } from "@/lib/types";

interface ReposPanelProps {
  repos: RepoSnapshot[];
  findings: VulnerabilityFinding[];
}

export function ReposPanel({ repos, findings }: ReposPanelProps) {
  const [search, setSearch] = useState("");
  const [selectedRepo, setSelectedRepo] = useState<RepoSnapshot | null>(null);
  const [sbomSearch, setSbomSearch] = useState("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return repos;
    return repos.filter(
      (r) =>
        r.fullName.toLowerCase().includes(q) ||
        r.primaryLanguage.toLowerCase().includes(q) ||
        r.frameworks.some((fw) => fw.toLowerCase().includes(q)) ||
        r.ecosystems.some((eco) => eco.toLowerCase().includes(q)) ||
        r.dependencies.some((d) => d.name.toLowerCase().includes(q)),
    );
  }, [repos, search]);

  const selectedRepoFindings = useMemo(() => {
    if (!selectedRepo) return [];
    return findings.filter(
      (f) => f.repoFullName === selectedRepo.fullName && f.status !== "dismissed",
    );
  }, [findings, selectedRepo]);

  const selectedRepoDeps = useMemo(() => {
    if (!selectedRepo) return [];
    const q = sbomSearch.trim().toLowerCase();
    if (!q) return selectedRepo.dependencies;
    return selectedRepo.dependencies.filter(
      (d) => d.name.toLowerCase().includes(q) || d.ecosystem.toLowerCase().includes(q),
    );
  }, [selectedRepo, sbomSearch]);

  return (
    <Card className="border-border/80 shadow-sm">
      <CardHeader className="pb-3">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle className="text-base">Repository Inventory &amp; Cached SBOMs</CardTitle>
            <CardDescription>
              Tech-stack fingerprints, runtime pins, Docker base images, and dependency counts used
              for instant Stage 1 filtering.
            </CardDescription>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search repo, language, package..."
              className="h-8 pl-8 text-xs"
            />
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border py-10 text-center">
            <FolderGit2 className="size-8 text-muted-foreground" />
            <p className="text-sm font-medium text-foreground">No repositories match your filter</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Repository</TableHead>
                  <TableHead>Stack &amp; Frameworks</TableHead>
                  <TableHead>Runtime Pinning</TableHead>
                  <TableHead>SBOM</TableHead>
                  <TableHead className="text-right">Open Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((repo) => {
                  const hasUnpinned =
                    repo.runtimes.length === 0 || repo.runtimes.some((rt) => !rt.pinned);
                  return (
                    <TableRow
                      key={repo.id}
                      className="cursor-pointer"
                      onClick={() => {
                        setSelectedRepo(repo);
                        setSbomSearch("");
                      }}
                    >
                      <TableCell>
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-xs font-semibold text-foreground">
                              {repo.fullName}
                            </span>
                            {repo.visibility === "private" ? (
                              <Lock className="size-3 text-muted-foreground" />
                            ) : (
                              <Unlock className="size-3 text-muted-foreground" />
                            )}
                          </div>
                          {repo.description && (
                            <p className="max-w-xs truncate text-xs text-muted-foreground">
                              {repo.description}
                            </p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          <Badge variant="secondary" className="text-[11px]">
                            {repo.primaryLanguage}
                          </Badge>
                          {repo.frameworks.slice(0, 2).map((fw) => (
                            <Badge key={fw} variant="outline" className="text-[11px]">
                              {fw}
                            </Badge>
                          ))}
                          {repo.dockerImages.length > 0 && (
                            <Badge variant="outline" className="gap-1 text-[11px]">
                              <Container className="size-2.5" />
                              Docker
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {repo.runtimes.length === 0 ? (
                          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                            <AlertTriangle className="size-3 text-amber-500" />
                            Not declared
                          </span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {repo.runtimes.slice(0, 2).map((rt, idx) => (
                              <Badge
                                key={`${rt.runtime}-${idx}`}
                                variant="outline"
                                className={`font-mono text-[11px] ${
                                  rt.pinned
                                    ? "border-emerald-500/30 text-emerald-700 dark:text-emerald-300"
                                    : "border-amber-500/30 text-amber-800 dark:text-amber-300"
                                }`}
                              >
                                {rt.runtime} {rt.version}
                              </Badge>
                            ))}
                            {hasUnpinned && repo.runtimes.every((rt) => rt.pinned) === false && (
                              <span className="sr-only">Unpinned runtime</span>
                            )}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Package className="size-3.5" />
                          <span className="font-medium text-foreground">
                            {repo.dependencies.length}
                          </span>
                          <span>pkgs</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        {repo.findingsCount === 0 ? (
                          <Badge className="border-emerald-500/30 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300">
                            Clean
                          </Badge>
                        ) : (
                          <div className="inline-flex items-center gap-1">
                            {repo.criticalCount > 0 && (
                              <Badge className="border-red-500/30 bg-red-500/15 text-red-700 dark:text-red-300">
                                {repo.criticalCount} Crit
                              </Badge>
                            )}
                            {repo.highCount > 0 && (
                              <Badge className="border-orange-500/30 bg-orange-500/15 text-orange-700 dark:text-orange-300">
                                {repo.highCount} High
                              </Badge>
                            )}
                            {repo.criticalCount === 0 && repo.highCount === 0 && (
                              <Badge variant="outline">{repo.findingsCount} Open</Badge>
                            )}
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      <Dialog
        open={selectedRepo !== null}
        onOpenChange={(open) => !open && setSelectedRepo(null)}
      >
        <DialogContent className="sm:max-w-2xl">
          {selectedRepo && (
            <>
              <DialogHeader>
                <div className="flex flex-wrap items-center justify-between gap-2 pr-6">
                  <DialogTitle className="font-mono text-base">{selectedRepo.fullName}</DialogTitle>
                  {selectedRepo.htmlUrl && (
                    <a
                      href={selectedRepo.htmlUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
                    >
                      Open on GitHub
                      <ExternalLink className="size-3" />
                    </a>
                  )}
                </div>
                <DialogDescription>
                  {selectedRepo.description ||
                    `${selectedRepo.primaryLanguage} repository (${selectedRepo.defaultBranch})`}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 text-xs">
                <div className="grid gap-3 rounded-lg border border-border bg-muted/25 p-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <div className="font-semibold text-foreground">Languages &amp; Frameworks</div>
                    <div className="flex flex-wrap gap-1">
                      {selectedRepo.languages.map((l) => (
                        <Badge key={l} variant="secondary" className="text-[11px]">
                          {l}
                        </Badge>
                      ))}
                      {selectedRepo.frameworks.map((f) => (
                        <Badge key={f} variant="outline" className="text-[11px]">
                          {f}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="font-semibold text-foreground">
                      Runtimes &amp; Container Images
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {selectedRepo.runtimes.map((rt, i) => (
                        <Badge
                          key={`${rt.runtime}-${i}`}
                          variant="outline"
                          className="font-mono text-[11px]"
                        >
                          {rt.runtime} {rt.version} ({rt.pinned ? "pinned" : "unpinned"})
                        </Badge>
                      ))}
                      {selectedRepo.dockerImages.map((img) => (
                        <Badge key={img} variant="secondary" className="font-mono text-[11px]">
                          FROM {img}
                        </Badge>
                      ))}
                      {selectedRepo.runtimes.length === 0 &&
                        selectedRepo.dockerImages.length === 0 && (
                          <span className="text-muted-foreground">No runtime pins or Dockerfile</span>
                        )}
                    </div>
                  </div>
                </div>

                {selectedRepo.keyFiles.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-1.5 font-semibold text-foreground">
                      <FileCode2 className="size-3.5" />
                      Indexed Security &amp; Config Files
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedRepo.keyFiles.map((file) => (
                        <span
                          key={file}
                          className="rounded border border-border bg-muted/40 px-2 py-0.5 font-mono text-[11px]"
                        >
                          {file}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selectedRepoFindings.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="font-semibold text-foreground">
                      Active Findings ({selectedRepoFindings.length})
                    </div>
                    <div className="space-y-1.5">
                      {selectedRepoFindings.map((f) => (
                        <div
                          key={f.id}
                          className="flex items-center justify-between gap-2 rounded-md border border-border px-2.5 py-2"
                        >
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <SeverityBadge severity={f.severity} />
                              <span className="font-mono font-semibold">{f.advisoryId}</span>
                            </div>
                            <p className="mt-0.5 truncate text-muted-foreground">{f.title}</p>
                          </div>
                          <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                            {f.packageName}@{f.installedVersion}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 font-semibold text-foreground">
                      <Box className="size-3.5" />
                      Indexed Dependencies ({selectedRepo.dependencies.length})
                    </div>
                    <Input
                      value={sbomSearch}
                      onChange={(e) => setSbomSearch(e.target.value)}
                      placeholder="Filter packages..."
                      className="h-7 w-44 text-xs"
                    />
                  </div>
                  <ScrollArea className="h-44 rounded-lg border border-border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Package</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>Ecosystem</TableHead>
                          <TableHead>Manifest</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {selectedRepoDeps.map((dep, idx) => (
                          <TableRow key={`${dep.ecosystem}:${dep.name}:${idx}`}>
                            <TableCell className="font-mono text-xs font-medium">
                              {dep.name}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{dep.version}</TableCell>
                            <TableCell className="text-xs">{dep.ecosystem}</TableCell>
                            <TableCell className="font-mono text-[11px] text-muted-foreground">
                              {dep.manifestPath}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
