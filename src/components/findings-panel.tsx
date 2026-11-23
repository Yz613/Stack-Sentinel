"use client";

import { useMemo, useState } from "react";
import { Check, ExternalLink, RotateCcw, Search, ShieldCheck, X } from "lucide-react";
import { FindingStatusBadge, SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { FindingStatus, VulnerabilityFinding } from "@/lib/types";

interface FindingsPanelProps {
  findings: VulnerabilityFinding[];
  onStatusChange: (findingId: string, status: FindingStatus) => Promise<void>;
}

export function FindingsPanel({ findings, onStatusChange }: FindingsPanelProps) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ACTIVE");
  const [selected, setSelected] = useState<VulnerabilityFinding | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
      if (statusFilter === "ACTIVE" && f.status === "dismissed") return false;
      if (statusFilter !== "ALL" && statusFilter !== "ACTIVE" && f.status !== statusFilter) {
        return false;
      }
      if (!q) return true;
      return (
        f.repoFullName.toLowerCase().includes(q) ||
        f.advisoryId.toLowerCase().includes(q) ||
        f.packageName.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.ecosystem.toLowerCase().includes(q)
      );
    });
  }, [findings, search, severityFilter, statusFilter]);

  async function handleStatus(findingId: string, nextStatus: FindingStatus) {
    setUpdatingId(findingId);
    try {
      await onStatusChange(findingId, nextStatus);
      if (selected?.id === findingId) {
        setSelected({ ...selected, status: nextStatus });
      }
    } finally {
      setUpdatingId(null);
    }
  }

  return (
    <Card className="border-border/80 shadow-sm">
      <CardHeader className="pb-3">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle className="text-base">Fleet Security Findings</CardTitle>
            <CardDescription>
              Known dependency CVEs, vulnerable base images, and unpinned runtime alerts across all
              repositories.
            </CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-full sm:w-56">
              <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter repo, CVE, package..."
                className="h-8 pl-8 text-xs"
              />
            </div>

            <Select
              value={severityFilter}
              onValueChange={(val) => setSeverityFilter(val ?? "ALL")}
            >
              <SelectTrigger className="w-32 text-xs">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ALL">All Severities</SelectItem>
                <SelectItem value="CRITICAL">Critical</SelectItem>
                <SelectItem value="HIGH">High</SelectItem>
                <SelectItem value="MEDIUM">Medium</SelectItem>
                <SelectItem value="LOW">Low</SelectItem>
              </SelectContent>
            </Select>

            <Select value={statusFilter} onValueChange={(val) => setStatusFilter(val ?? "ACTIVE")}>
              <SelectTrigger className="w-36 text-xs">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ACTIVE">Open &amp; Ack</SelectItem>
                <SelectItem value="open">Open Only</SelectItem>
                <SelectItem value="acknowledged">Acknowledged</SelectItem>
                <SelectItem value="dismissed">Dismissed</SelectItem>
                <SelectItem value="ALL">All Statuses</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border py-10 text-center">
            <ShieldCheck className="size-8 text-emerald-600" />
            <p className="text-sm font-medium text-foreground">No matching findings</p>
            <p className="text-xs text-muted-foreground">
              {findings.length === 0
                ? "Your synced fleet currently has zero detected vulnerabilities."
                : "Adjust your severity, status, or search filters to view other findings."}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-28">Severity</TableHead>
                  <TableHead>Advisory &amp; Title</TableHead>
                  <TableHead>Repository</TableHead>
                  <TableHead>Package / Version</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Triage</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((f) => {
                  const busy = updatingId === f.id;
                  return (
                    <TableRow
                      key={f.id}
                      className="cursor-pointer"
                      onClick={() => setSelected(f)}
                    >
                      <TableCell>
                        <SeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="max-w-sm">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-xs font-semibold">{f.advisoryId}</span>
                            <Badge variant="secondary" className="text-[10px]">
                              {f.ecosystem}
                            </Badge>
                          </div>
                          <p className="truncate text-xs text-muted-foreground">{f.title}</p>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{f.repoFullName}</TableCell>
                      <TableCell>
                        <div className="space-y-0.5 font-mono text-xs">
                          <div className="font-medium text-foreground">
                            {f.packageName}@{f.installedVersion}
                          </div>
                          {f.fixedVersion && (
                            <div className="text-[11px] text-emerald-700 dark:text-emerald-400">
                              Fix: {f.fixedVersion}
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <FindingStatusBadge status={f.status} />
                      </TableCell>
                      <TableCell
                        className="text-right"
                        onClick={(e) => {
                          e.stopPropagation();
                        }}
                      >
                        <div className="inline-flex items-center gap-1">
                          {f.status !== "acknowledged" && (
                            <Button
                              size="xs"
                              variant="outline"
                              disabled={busy}
                              onClick={() => void handleStatus(f.id, "acknowledged")}
                              title="Acknowledge"
                            >
                              <Check className="size-3" />
                              Ack
                            </Button>
                          )}
                          {f.status !== "dismissed" ? (
                            <Button
                              size="xs"
                              variant="ghost"
                              disabled={busy}
                              onClick={() => void handleStatus(f.id, "dismissed")}
                              title="Dismiss finding"
                            >
                              <X className="size-3" />
                            </Button>
                          ) : (
                            <Button
                              size="xs"
                              variant="outline"
                              disabled={busy}
                              onClick={() => void handleStatus(f.id, "open")}
                              title="Reopen finding"
                            >
                              <RotateCcw className="size-3" />
                              Reopen
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      <Dialog open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="sm:max-w-lg">
          {selected && (
            <>
              <DialogHeader>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <Badge variant="outline" className="font-mono text-xs">
                    {selected.advisoryId}
                  </Badge>
                  <FindingStatusBadge status={selected.status} />
                </div>
                <DialogTitle className="pt-1 text-base">{selected.title}</DialogTitle>
                <DialogDescription className="font-mono text-xs">
                  {selected.repoFullName} · {selected.manifestPath || selected.ecosystem}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3 text-xs">
                <p className="leading-relaxed text-muted-foreground">
                  {selected.summary || "No extended summary returned by advisory database."}
                </p>

                <div className="grid grid-cols-2 gap-2 rounded-lg border border-border bg-muted/30 p-3">
                  <div>
                    <div className="text-muted-foreground">Package</div>
                    <div className="font-mono font-semibold text-foreground">
                      {selected.packageName}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Ecosystem</div>
                    <div className="font-medium text-foreground">{selected.ecosystem}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Installed Version</div>
                    <div className="font-mono font-medium text-foreground">
                      {selected.installedVersion}
                    </div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Fixed Version</div>
                    <div className="font-mono font-medium text-emerald-700 dark:text-emerald-400">
                      {selected.fixedVersion || "Check advisory"}
                    </div>
                  </div>
                </div>

                {selected.aliases.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-muted-foreground">Aliases:</span>
                    {selected.aliases.map((alias) => (
                      <Badge key={alias} variant="secondary" className="font-mono text-[11px]">
                        {alias}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>

              <DialogFooter className="gap-2 sm:justify-between">
                <div>
                  {selected.referenceUrl && (
                    <a
                      href={selected.referenceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
                    >
                      View Official Advisory
                      <ExternalLink className="size-3" />
                    </a>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {selected.status !== "acknowledged" && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={updatingId === selected.id}
                      onClick={() => void handleStatus(selected.id, "acknowledged")}
                    >
                      Acknowledge
                    </Button>
                  )}
                  {selected.status !== "dismissed" ? (
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={updatingId === selected.id}
                      onClick={() => void handleStatus(selected.id, "dismissed")}
                    >
                      Dismiss
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={updatingId === selected.id}
                      onClick={() => void handleStatus(selected.id, "open")}
                    >
                      Reopen
                    </Button>
                  )}
                </div>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
