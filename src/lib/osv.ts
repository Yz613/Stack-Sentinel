import { safeExternalUrl } from "./security";
import type { DependencyItem, Severity, VulnerabilityFinding } from "./types";

const OSV_API_BASE = "https://api.osv.dev/v1";
const SAFE_ID_RE = /^[A-Za-z0-9._-]{4,64}$/;

interface OsvAffectedRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvAffected {
  package?: {
    name?: string;
    ecosystem?: string;
  };
  ranges?: Array<{
    type?: string;
    events?: OsvAffectedRangeEvent[];
  }>;
}

export interface OsvVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: {
    severity?: string;
  };
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url?: string }>;
}

export function parseOsvSeverity(vuln: OsvVulnerability): Severity {
  const dbSev = vuln.database_specific?.severity?.toUpperCase();
  if (dbSev === "CRITICAL" || dbSev === "HIGH" || dbSev === "MODERATE" || dbSev === "MEDIUM" || dbSev === "LOW") {
    return dbSev === "MODERATE" ? "MEDIUM" : (dbSev as Severity);
  }
  const cvssText = vuln.severity?.[0]?.score ?? "";
  const numeric = Number.parseFloat(cvssText);
  if (!Number.isNaN(numeric)) {
    if (numeric >= 9.0) return "CRITICAL";
    if (numeric >= 7.0) return "HIGH";
    if (numeric >= 4.0) return "MEDIUM";
    return "LOW";
  }
  const text = `${vuln.summary ?? ""} ${vuln.details ?? ""}`.toLowerCase();
  if (text.includes("remote code execution") || text.includes("auth bypass") || text.includes("critical")) {
    return "CRITICAL";
  }
  if (text.includes("ssrf") || text.includes("sql injection") || text.includes("privilege escalation")) {
    return "HIGH";
  }
  return "MEDIUM";
}

export function extractFixedVersion(vuln: OsvVulnerability, packageName?: string): string {
  for (const aff of vuln.affected ?? []) {
    if (packageName && aff.package?.name?.toLowerCase() !== packageName.toLowerCase()) {
      continue;
    }
    for (const range of aff.ranges ?? []) {
      for (const evt of range.events ?? []) {
        if (evt.fixed) return evt.fixed;
      }
    }
  }
  return "";
}

export function extractReferenceUrl(vuln: OsvVulnerability): string {
  const advisoryRef = vuln.references?.find((r) => r.type === "ADVISORY")?.url;
  const firstRef = vuln.references?.[0]?.url;
  const fallback = SAFE_ID_RE.test(vuln.id) ? `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}` : "";
  return safeExternalUrl(advisoryRef ?? firstRef ?? fallback);
}

/**
 * Fetches a single advisory by validated CVE/GHSA/OSV ID from OSV.dev.
 * Never fetches arbitrary user URLs.
 */
export async function fetchOsvAdvisoryById(id: string): Promise<OsvVulnerability | null> {
  const trimmed = id.trim().toUpperCase();
  if (!SAFE_ID_RE.test(trimmed)) return null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(`${OSV_API_BASE}/vulns/${encodeURIComponent(trimmed)}`, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const data = (await res.json()) as OsvVulnerability;
    if (!data?.id) return null;
    return data;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Queries OSV.dev /v1/querybatch for exact dependency versions across a repository.
 */
export async function queryOsvForDependencies(
  repoFullName: string,
  dependencies: DependencyItem[],
): Promise<VulnerabilityFinding[]> {
  const queryable = dependencies
    .filter(
      (d) =>
        d.version &&
        d.version !== "unpinned" &&
        /^\d+\.\d+/.test(d.version) &&
        ["npm", "Packagist", "PyPI", "Go", "crates.io"].includes(d.ecosystem),
    )
    .slice(0, 80);

  if (queryable.length === 0) return [];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const res = await fetch(`${OSV_API_BASE}/querybatch`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        queries: queryable.map((d) => ({
          package: { name: d.name, ecosystem: d.ecosystem },
          version: d.version,
        })),
      }),
      signal: controller.signal,
    });

    if (!res.ok) return [];
    const payload = (await res.json()) as {
      results?: Array<{ vulns?: Array<{ id: string }> }>;
    };

    const hits: Array<{ dep: DependencyItem; vulnId: string }> = [];
    for (let i = 0; i < queryable.length; i++) {
      const vulns = payload.results?.[i]?.vulns ?? [];
      for (const v of vulns.slice(0, 3)) {
        if (v.id && SAFE_ID_RE.test(v.id)) {
          hits.push({ dep: queryable[i], vulnId: v.id });
        }
      }
    }

    const uniqueIds = [...new Set(hits.map((h) => h.vulnId))].slice(0, 20);
    const detailsMap = new Map<string, OsvVulnerability>();

    await Promise.all(
      uniqueIds.map(async (vulnId) => {
        const detail = await fetchOsvAdvisoryById(vulnId);
        if (detail) detailsMap.set(vulnId, detail);
      }),
    );

    const findings: VulnerabilityFinding[] = [];
    const seen = new Set<string>();

    for (const { dep, vulnId } of hits) {
      const detail = detailsMap.get(vulnId);
      const primaryId =
        detail?.aliases?.find((a) => a.startsWith("CVE-")) ?? detail?.id ?? vulnId;
      const dedupeKey = `${repoFullName}:${primaryId}:${dep.name}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      findings.push({
        id: `${repoFullName}::${primaryId}::${dep.name}`.toLowerCase(),
        repoFullName,
        advisoryId: primaryId,
        aliases: detail?.aliases ?? (primaryId !== vulnId ? [vulnId] : []),
        title:
          detail?.summary ||
          `Known vulnerability ${primaryId} in ${dep.name}@${dep.version}`,
        summary: (detail?.details ?? detail?.summary ?? "").slice(0, 600),
        severity: detail ? parseOsvSeverity(detail) : "MEDIUM",
        category: "dependency",
        ecosystem: dep.ecosystem,
        packageName: dep.name,
        installedVersion: dep.version,
        fixedVersion: detail ? extractFixedVersion(detail, dep.name) : "",
        manifestPath: dep.manifestPath,
        referenceUrl: detail
          ? extractReferenceUrl(detail)
          : `https://osv.dev/vulnerability/${encodeURIComponent(vulnId)}`,
        status: "open",
        detectedAt: new Date().toISOString(),
      });
    }

    return findings;
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}
