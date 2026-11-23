"use client";

import { AlertOctagon, AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { FindingStatus, Severity, VerdictStatus } from "@/lib/types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  switch (severity) {
    case "CRITICAL":
      return (
        <Badge className="border-red-500/30 bg-red-500/15 text-red-700 dark:text-red-300">
          <AlertOctagon className="size-3" />
          Critical
        </Badge>
      );
    case "HIGH":
      return (
        <Badge className="border-orange-500/30 bg-orange-500/15 text-orange-700 dark:text-orange-300">
          <ShieldAlert className="size-3" />
          High
        </Badge>
      );
    case "MEDIUM":
      return (
        <Badge className="border-amber-500/30 bg-amber-500/15 text-amber-800 dark:text-amber-300">
          <AlertTriangle className="size-3" />
          Medium
        </Badge>
      );
    case "LOW":
      return (
        <Badge className="border-sky-500/30 bg-sky-500/15 text-sky-700 dark:text-sky-300">
          <Info className="size-3" />
          Low
        </Badge>
      );
  }
}

export function VerdictBadge({ verdict }: { verdict: VerdictStatus }) {
  switch (verdict) {
    case "affected":
      return (
        <Badge className="border-red-500/30 bg-red-500/15 text-red-700 dark:text-red-300">
          <AlertOctagon className="size-3" />
          Affected
        </Badge>
      );
    case "needs_review":
      return (
        <Badge className="border-amber-500/30 bg-amber-500/15 text-amber-800 dark:text-amber-300">
          <AlertTriangle className="size-3" />
          Needs Check
        </Badge>
      );
    case "cleared":
      return (
        <Badge className="border-emerald-500/30 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300">
          <CheckCircle2 className="size-3" />
          Cleared
        </Badge>
      );
  }
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  switch (status) {
    case "open":
      return (
        <Badge variant="outline" className="border-red-500/30 text-red-700 dark:text-red-300">
          Open
        </Badge>
      );
    case "acknowledged":
      return (
        <Badge variant="outline" className="border-amber-500/30 text-amber-800 dark:text-amber-300">
          Acknowledged
        </Badge>
      );
    case "dismissed":
      return (
        <Badge variant="outline" className="text-muted-foreground">
          Dismissed
        </Badge>
      );
  }
}
