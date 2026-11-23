import { loadFleetDashboard } from "@/lib/fleet-service";
import {
  getViewerDisplay,
  getViewerOwnerKey,
  privateJson,
  requireViewer,
} from "@/lib/security";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const viewer = await requireViewer(request);
  if (viewer instanceof Response) return viewer;

  try {
    const ownerSub = getViewerOwnerKey(viewer);
    const data = await loadFleetDashboard(ownerSub);
    return privateJson({
      ...data,
      viewer: getViewerDisplay(viewer),
    });
  } catch {
    return privateJson({ error: "Failed to load fleet security dashboard" }, 500);
  }
}
