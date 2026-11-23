"use client";

import { useEffect, useState } from "react";
import { ExternalLink, Loader2, Radar, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ThreatWatchRunRecord } from "@/lib/threat-watch";

interface ThreatWatchStatusPayload {
  feedUrl: string;
  pageUrl: string;
  cronSchedule: string;
  seenCount: number;
  runs: ThreatWatchRunRecord[];
}

export function ThreatWatchPanel({ onScanComplete }: { onScanComplete?: () => void }) {
  const [status, setStatus] = useState<ThreatWatchStatusPayload | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function init() {
      try {
        const res = await fetch("/api/threat-watch", { cache: "no-store" });
        if (!active || !res.ok) return;
        const json = (await res.json()) as ThreatWatchStatusPayload;
        if (active) setStatus(json);
      } catch {
        // Ignore initial background fetch errors
      }
    }
    void init();
    return () => {
      active = false;
    };
  }, []);

  async function handleRunNow() {
    setRunning(true);
    setError(null);
    try {
      const res = await fetch("/api/threat-watch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ force: false }),
      });
      const json = (await res.json()) as {
        status?: ThreatWatchStatusPayload;
        error?: string;
      };
      if (!res.ok) {
        setError(json.error ?? "Threat Watch run failed.");
        return;
      }
      if (json.status) setStatus(json.status);
      onScanComplete?.();
    } catch {
      setError("Network error running Threat Watch.");
    } finally {
      setRunning(false);
    }
  }

  const latestRun = status?.runs[0] ?? null;

  return (
    <Card className="border-border/60 bg-card/60">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3 pb-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Radar className="h-4 w-4 text-emerald-400" />
            <CardTitle className="text-base">Helix Threat Watch (Daily Cron)</CardTitle>
            <Badge variant="outline" className="text-xs font-normal">
              9:00 AM EST · Dry-run
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Checks{" "}
            <a
              href={status?.pageUrl ?? "https://helix.ml/threat-watch?range=2026&chart=line"}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 underline underline-offset-2 hover:text-foreground"
            >
              helix.ml/threat-watch
              <ExternalLink className="h-3 w-3" />
            </a>{" "}
            for new vulnerabilities, scans your fleet, and records dry-run patch plans.
          </CardDescription>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={handleRunNow}
          disabled={running}
          className="gap-1.5"
        >
          {running ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <RefreshCw className="h-3.5 w-3.5" />
          )}
          {running ? "Scanning..." : "Run Threat Watch Now"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 pt-0 text-xs">
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive">
            {error}
          </div>
        )}
        {latestRun ? (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 text-muted-foreground">
              <span>{latestRun.summary}</span>
              <span>
                {new Date(latestRun.createdAt).toLocaleString()} · {latestRun.triggerSource}
              </span>
            </div>
            {latestRun.patchPlans.length > 0 && (
              <div className="space-y-1.5 rounded-md border border-border/60 bg-background/50 p-2.5">
                <div className="font-medium text-foreground">
                  Dry-Run Patch Plans ({latestRun.patchPlans.length})
                </div>
                {latestRun.patchPlans.slice(0, 6).map((plan, idx) => (
                  <div
                    key={`${plan.repoFullName}-${plan.advisoryId}-${idx}`}
                    className="flex flex-col gap-0.5 border-t border-border/40 pt-1.5 first:border-t-0 first:pt-0"
                  >
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge variant="secondary" className="text-[10px]">
                        {plan.severity}
                      </Badge>
                      <span className="font-medium text-foreground">{plan.repoFullName}</span>
                      <span className="text-muted-foreground">· {plan.advisoryId}</span>
                    </div>
                    <div className="text-muted-foreground">{plan.suggestedPatch}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <p className="text-muted-foreground">
            No Threat Watch runs recorded yet. Click &ldquo;Run Threat Watch Now&rdquo; or wait for the 9:00 AM EST cron trigger.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
