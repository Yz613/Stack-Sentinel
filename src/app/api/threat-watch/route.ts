import { z } from "zod";
import {
  getViewerOwnerKey,
  privateJson,
  requireViewer,
  verifySameOrigin,
} from "@/lib/security";
import { loadThreatWatchStatus, runThreatWatchScan } from "@/lib/threat-watch";

export const dynamic = "force-dynamic";

const postSchema = z.object({
  force: z.boolean().optional().default(false),
});

export async function GET(request: Request) {
  const viewer = await requireViewer(request);
  if (viewer instanceof Response) return viewer;

  try {
    const ownerSub = getViewerOwnerKey(viewer);
    const status = await loadThreatWatchStatus(ownerSub);
    return privateJson(status);
  } catch {
    return privateJson({ error: "Failed to load Threat Watch status" }, 500);
  }
}

export async function POST(request: Request) {
  const csrf = verifySameOrigin(request);
  if (csrf) return csrf;

  const viewer = await requireViewer(request);
  if (viewer instanceof Response) return viewer;

  let body: unknown = {};
  try {
    const text = await request.text();
    if (text.trim()) body = JSON.parse(text);
  } catch {
    return privateJson({ error: "Invalid JSON body" }, 400);
  }

  const parsed = postSchema.safeParse(body);
  if (!parsed.success) {
    return privateJson({ error: "Invalid Threat Watch request" }, 400);
  }

  try {
    const ownerSub = getViewerOwnerKey(viewer);
    const run = await runThreatWatchScan(ownerSub, {
      trigger: "manual",
      force: parsed.data.force,
    });
    const status = await loadThreatWatchStatus(ownerSub);
    return privateJson({ run, status }, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Threat Watch scan failed";
    return privateJson({ error: message }, 500);
  }
}
