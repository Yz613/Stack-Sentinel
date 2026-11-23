import { deleteAdvisoryCheck } from "@/lib/fleet-service";
import {
  getViewerOwnerKey,
  privateJson,
  requireViewer,
  verifySameOrigin,
} from "@/lib/security";

export const dynamic = "force-dynamic";

export async function DELETE(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const csrf = verifySameOrigin(request);
  if (csrf) return csrf;

  const viewer = await requireViewer(request);
  if (viewer instanceof Response) return viewer;

  const { id } = await context.params;
  if (!id || id.length > 128) {
    return privateJson({ error: "Invalid advisory check id" }, 400);
  }

  try {
    const deleted = await deleteAdvisoryCheck(getViewerOwnerKey(viewer), id);
    if (!deleted) {
      return privateJson({ error: "Advisory check not found" }, 404);
    }
    return privateJson({ deleted: true });
  } catch {
    return privateJson({ error: "Failed to delete advisory check" }, 500);
  }
}
