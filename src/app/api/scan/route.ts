import { evaluateAdvisoryAgainstFleet, parseAdvisoryInput } from "@/lib/advisory-engine";
import { fetchGitHubUser, scanLiveGitHubFleet } from "@/lib/github-scanner";
import { privateJson, verifySameOrigin } from "@/lib/security";
import { THREAT_WATCH_FEED_URL } from "@/lib/threat-watch";

export const dynamic = "force-dynamic";

interface HelixFeedResponse {
  items?: Array<{
    id?: string;
    url?: string;
    title?: string;
    summary?: string;
    _threatwatch?: {
      category?: string;
      cveIds?: string[];
      identifiers?: string[];
      product?: string;
      severity?: string;
      stacks?: string[];
      summary?: string;
    };
  }>;
}

/**
 * Stateless, per-user GitHub + Threat Watch scan.
 * Never persists the user's GitHub token, repositories, or findings to shared D1.
 */
export async function POST(request: Request) {
  const csrf = verifySameOrigin(request);
  if (csrf) return csrf;

  const token = request.headers.get("x-github-token")?.trim() ?? "";
  if (!token) {
    return privateJson({ error: "GitHub token is required." }, 401);
  }

  const user = await fetchGitHubUser(token);
  if (!user) {
    return privateJson(
      { error: "Invalid or expired GitHub token. Please check your Personal Access Token." },
      401,
    );
  }

  try {
    const started = Date.now();
    const { repos, findings } = await scanLiveGitHubFleet(`user:${user.login}`, token);

    let feedItemsChecked = 0;
    let threatWatchMatched = 0;
    try {
      const feedRes = await fetch(THREAT_WATCH_FEED_URL, {
        headers: {
          accept: "application/json",
          "user-agent": "StackSentinel-Security-Scanner",
        },
        signal: AbortSignal.timeout(10000),
      });
      if (feedRes.ok) {
        const feed = (await feedRes.json()) as HelixFeedResponse;
        const actionable = (feed.items ?? []).filter((item) => {
          const cat = item._threatwatch?.category ?? "";
          return cat === "patch" || cat === "supply-chain";
        });
        feedItemsChecked = actionable.length;

        for (const item of actionable.slice(0, 3)) {
          const tw = item._threatwatch;
          const ids = [...(tw?.cveIds ?? []), ...(tw?.identifiers ?? [])].filter(Boolean);
          const query = [
            ids.join(" "),
            item.title ?? "",
            tw?.product ? `Product: ${tw.product}` : "",
            tw?.summary ?? item.summary ?? "",
          ]
            .filter(Boolean)
            .join(" — ")
            .slice(0, 580);
          if (query.length < 2) continue;

          const parsed = await parseAdvisoryInput(query);
          const verdicts = await evaluateAdvisoryAgainstFleet(parsed, repos, false);
          threatWatchMatched += verdicts.filter((v) => v.verdict === "affected").length;
        }
      }
    } catch {
      // Non-fatal: Threat Watch feed check is best-effort during live scan
    }

    const scannedAt = new Date().toISOString();
    return privateJson({
      user,
      repos,
      findings,
      scannedAt,
      durationMs: Date.now() - started,
      threatWatch: {
        checkedAt: scannedAt,
        feedItemsChecked,
        matchedCount: threatWatchMatched,
        summary:
          feedItemsChecked > 0
            ? `Checked ${feedItemsChecked} Threat Watch advisories (${threatWatchMatched} affected)`
            : "Threat Watch feed checked",
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Scan failed.";
    return privateJson({ error: message }, 500);
  }
}
