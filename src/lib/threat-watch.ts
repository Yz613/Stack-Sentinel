import { dbAll, dbBatch, dbRun } from "./db";
import { loadFleetDashboard, runAndSaveAdvisoryCheck, syncFleetForOwner } from "./fleet-service";
import type { RepoAdvisoryVerdict } from "./types";

export const THREAT_WATCH_FEED_URL = "https://helix.ml/threat-watch/feed.json";
export const THREAT_WATCH_PAGE_URL = "https://helix.ml/threat-watch?range=2026&chart=line";

interface HelixThreatWatchMeta {
  category?: string;
  cveIds?: string[];
  identifiers?: string[];
  patchStatus?: string;
  product?: string;
  severity?: string;
  slug?: string;
  stacks?: string[];
  startedAt?: string;
  status?: string;
  summary?: string;
  latestUpdate?: {
    date?: string;
    title?: string;
  };
}

interface HelixFeedItem {
  id?: string;
  url?: string;
  title?: string;
  date_published?: string;
  date_modified?: string;
  summary?: string;
  _threatwatch?: HelixThreatWatchMeta;
}

interface HelixFeedResponse {
  items?: HelixFeedItem[];
}

export interface ThreatWatchPatchPlan {
  repoFullName: string;
  repoUrl: string;
  advisoryId: string;
  advisoryTitle: string;
  severity: string;
  category: string;
  verdict: "affected" | "needs_review";
  matchedPackages: Array<{
    name: string;
    ecosystem: string;
    installedVersion: string;
    fixedVersion?: string;
    manifestPath: string;
  }>;
  suggestedPatch: string;
  referenceUrl: string;
  dryRun: true;
}

export interface ThreatWatchRunRecord {
  id: string;
  triggerSource: string;
  feedItemsChecked: number;
  newIncidentsCount: number;
  reposScanned: number;
  affectedReposCount: number;
  patchPlans: ThreatWatchPatchPlan[];
  summary: string;
  createdAt: string;
}

interface ThreatWatchRunRow {
  id: string;
  trigger_source: string;
  feed_items_checked: number;
  new_incidents_count: number;
  repos_scanned: number;
  affected_repos_count: number;
  patch_plans_json: string;
  summary: string;
  created_at: string;
}

function buildAdvisoryQuery(item: HelixFeedItem): string {
  const tw = item._threatwatch;
  const ids = [
    ...(tw?.cveIds ?? []),
    ...(tw?.identifiers ?? []),
  ].filter(Boolean);
  const parts = [
    ids.join(" "),
    item.title ?? tw?.latestUpdate?.title ?? "",
    tw?.product ? `Product: ${tw.product}` : "",
    tw?.stacks?.length ? `Stacks: ${tw.stacks.join(", ")}` : "",
    tw?.summary ?? item.summary ?? "",
  ].filter(Boolean);
  return parts.join(" — ").slice(0, 580);
}

function buildSuggestedPatch(
  item: HelixFeedItem,
  verdict: RepoAdvisoryVerdict,
): string {
  const tw = item._threatwatch;
  if (verdict.matchedPackages.length > 0) {
    const upgrades = verdict.matchedPackages.map((pkg) => {
      if (pkg.fixedVersion) {
        return `Upgrade ${pkg.name} (${pkg.installedVersion} -> ${pkg.fixedVersion}) in ${pkg.manifestPath || "manifest"}`;
      }
      if (tw?.patchStatus === "no-fix-needed" && tw.category === "supply-chain") {
        return `Remove compromised package ${pkg.name}@${pkg.installedVersion} from ${pkg.manifestPath || "manifest"} immediately`;
      }
      return `Review/pin ${pkg.name}@${pkg.installedVersion} in ${pkg.manifestPath || "manifest"}`;
    });
    return `${upgrades.join("; ")} [dry-run only]`;
  }

  if (tw?.patchStatus === "no-fix-needed" && tw.category === "supply-chain") {
    return `Check lockfiles for ${tw.product ?? item.title ?? "compromised package"} and remove if present [dry-run only]`;
  }

  return `${verdict.remediation || verdict.stage1Reason || "Review advisory signals"} (${item.url ?? THREAT_WATCH_PAGE_URL}) [dry-run only]`;
}

export async function runThreatWatchScan(
  ownerSub: string,
  options?: { trigger?: "cron" | "manual"; cron?: string; force?: boolean },
): Promise<ThreatWatchRunRecord> {
  const triggerSource = options?.trigger === "cron"
    ? `cron:${options.cron ?? "0 14 * * *"}`
    : "manual";

  const feedRes = await fetch(THREAT_WATCH_FEED_URL, {
    headers: {
      accept: "application/json",
      "user-agent": "stack-sentinel/1.0 (+https://stack-sentinel.yehudazahler.workers.dev)",
    },
    signal: AbortSignal.timeout(15000),
  });

  if (!feedRes.ok) {
    throw new Error(`Helix Threat Watch feed returned HTTP ${feedRes.status}`);
  }

  const feed = (await feedRes.json()) as HelixFeedResponse;
  const allItems = Array.isArray(feed.items) ? feed.items : [];
  const actionableItems = allItems.filter((item) => {
    const cat = item._threatwatch?.category ?? "";
    return cat === "patch" || cat === "supply-chain";
  });

  const seenRows = await dbAll<{ id: string }>(
    "SELECT id FROM threat_watch_seen WHERE owner_sub = ?",
    [ownerSub],
  );
  const seenIds = new Set(seenRows.map((r) => r.id));
  const isFirstRun = seenIds.size === 0;

  const unseenItems = actionableItems.filter((item) => {
    const key = item._threatwatch?.slug ?? item.id ?? item.url ?? "";
    return key !== "" && !seenIds.has(`${ownerSub}:${key}`);
  });

  // On initial baseline, evaluate the 3 most recent vulnerabilities and mark the rest as seen
  // so subsequent daily runs only scan newly published vulnerabilities.
  const maxEvaluate = isFirstRun ? 3 : 5;
  const itemsToEvaluate = options?.force && unseenItems.length === 0
    ? actionableItems.slice(0, 3)
    : unseenItems.slice(0, maxEvaluate);

  let reposScanned = 0;
  const patchPlans: ThreatWatchPatchPlan[] = [];

  if (itemsToEvaluate.length > 0) {
    try {
      const synced = await syncFleetForOwner(ownerSub);
      reposScanned = synced.scanRun.reposScanned;
    } catch (err) {
      console.warn("[threat-watch] syncFleetForOwner fallback to cached D1:", err);
      const dashboard = await loadFleetDashboard(ownerSub);
      reposScanned = dashboard.repos.length;
    }

    for (const item of itemsToEvaluate) {
      const query = buildAdvisoryQuery(item);
      if (query.length < 2) continue;

      const check = await runAndSaveAdvisoryCheck(ownerSub, query, false);
      const tw = item._threatwatch;
      const advisoryId =
        tw?.cveIds?.[0] ??
        tw?.identifiers?.[0] ??
        tw?.slug ??
        item.id ??
        "threat-watch";

      for (const verdict of check.results) {
        if (verdict.verdict === "affected" || verdict.verdict === "needs_review") {
          patchPlans.push({
            repoFullName: verdict.repoFullName,
            repoUrl: verdict.htmlUrl,
            advisoryId,
            advisoryTitle: item.title ?? tw?.latestUpdate?.title ?? advisoryId,
            severity: (tw?.severity ?? "high").toUpperCase(),
            category: tw?.category ?? "patch",
            verdict: verdict.verdict,
            matchedPackages: verdict.matchedPackages,
            suggestedPatch: buildSuggestedPatch(item, verdict),
            referenceUrl: item.url ?? THREAT_WATCH_PAGE_URL,
            dryRun: true,
          });
        }
      }
    }
  } else {
    const dashboard = await loadFleetDashboard(ownerSub);
    reposScanned = dashboard.repos.length;
  }

  // Record all unseen items in threat_watch_seen so they aren't re-processed tomorrow.
  if (unseenItems.length > 0) {
    const nowIso = new Date().toISOString();
    const seenStatements = unseenItems.slice(0, 200).map((item) => {
      const tw = item._threatwatch;
      const key = tw?.slug ?? item.id ?? item.url ?? crypto.randomUUID();
      return {
        sql: `INSERT OR IGNORE INTO threat_watch_seen (
          id, owner_sub, title, category, severity, identifiers_json, started_at, first_seen_at
        ) VALUES (?,?,?,?,?,?,?,?)`,
        params: [
          `${ownerSub}:${key}`,
          ownerSub,
          item.title ?? key,
          tw?.category ?? "patch",
          (tw?.severity ?? "medium").toUpperCase(),
          JSON.stringify([...(tw?.cveIds ?? []), ...(tw?.identifiers ?? [])]),
          tw?.startedAt ?? item.date_published ?? "",
          nowIso,
        ],
      };
    });
    await dbBatch(seenStatements);
  }

  const affectedReposCount = new Set(
    patchPlans.filter((p) => p.verdict === "affected").map((p) => p.repoFullName),
  ).size;

  const runId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const summary = itemsToEvaluate.length === 0
    ? `Checked ${actionableItems.length} Threat Watch advisories — no new vulnerabilities since last run.`
    : `Checked ${actionableItems.length} advisories, scanned ${itemsToEvaluate.length} ${isFirstRun ? "latest" : "new"} vulnerability item(s) across ${reposScanned} repos (${affectedReposCount} affected, ${patchPlans.length} dry-run patch plan(s)).`;

  await dbRun(
    `INSERT INTO threat_watch_runs (
      id, owner_sub, trigger_source, feed_items_checked, new_incidents_count,
      repos_scanned, affected_repos_count, patch_plans_json, summary, created_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [
      runId,
      ownerSub,
      triggerSource,
      actionableItems.length,
      unseenItems.length,
      reposScanned,
      affectedReposCount,
      JSON.stringify(patchPlans),
      summary,
      createdAt,
    ],
  );

  return {
    id: runId,
    triggerSource,
    feedItemsChecked: actionableItems.length,
    newIncidentsCount: unseenItems.length,
    reposScanned,
    affectedReposCount,
    patchPlans,
    summary,
    createdAt,
  };
}

export async function loadThreatWatchStatus(ownerSub: string): Promise<{
  feedUrl: string;
  pageUrl: string;
  cronSchedule: string;
  seenCount: number;
  runs: ThreatWatchRunRecord[];
}> {
  const [seenCountRows, runRows] = await Promise.all([
    dbAll<{ count: number }>(
      "SELECT COUNT(*) AS count FROM threat_watch_seen WHERE owner_sub = ?",
      [ownerSub],
    ),
    dbAll<ThreatWatchRunRow>(
      "SELECT * FROM threat_watch_runs WHERE owner_sub = ? ORDER BY created_at DESC LIMIT 10",
      [ownerSub],
    ),
  ]);

  const runs: ThreatWatchRunRecord[] = runRows.map((row) => {
    let patchPlans: ThreatWatchPatchPlan[] = [];
    try {
      patchPlans = JSON.parse(row.patch_plans_json) as ThreatWatchPatchPlan[];
    } catch {
      patchPlans = [];
    }
    return {
      id: row.id,
      triggerSource: row.trigger_source,
      feedItemsChecked: Number(row.feed_items_checked),
      newIncidentsCount: Number(row.new_incidents_count),
      reposScanned: Number(row.repos_scanned),
      affectedReposCount: Number(row.affected_repos_count),
      patchPlans,
      summary: row.summary,
      createdAt: String(row.created_at),
    };
  });

  return {
    feedUrl: THREAT_WATCH_FEED_URL,
    pageUrl: THREAT_WATCH_PAGE_URL,
    cronSchedule: "0 14 * * * (9:00 AM EST / 14:00 UTC daily)",
    seenCount: Number(seenCountRows[0]?.count ?? 0),
    runs,
  };
}
