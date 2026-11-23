import { loadFleetDashboard, syncFleetForOwner } from "@/lib/fleet-service";
import {
  getViewerDisplay,
  getViewerOwnerKey,
  privateJson,
  requireViewer,
  verifySameOrigin,
} from "@/lib/security";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const csrf = verifySameOrigin(request);
  if (csrf) return csrf;

  const viewer = await requireViewer(request);
  if (viewer instanceof Response) return viewer;

  try {
    const ownerSub = getViewerOwnerKey(viewer);
    const { scanRun } = await syncFleetForOwner(ownerSub);
    const dashboard = await loadFleetDashboard(ownerSub);
    return privateJson({
      scanRun,
      dashboard: {
        ...dashboard,
        viewer: getViewerDisplay(viewer),
      },
    });
  } catch (err) {
    const message =
      err instanceof Error && err.message.includes("GitHub API")
        ? err.message
        : "Fleet sync failed. Please try again.";
    return privateJson({ error: message }, 502);
  }
}
