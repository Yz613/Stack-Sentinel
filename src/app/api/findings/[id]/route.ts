import { z } from "zod";
import { updateFindingStatus } from "@/lib/fleet-service";
import {
  getViewerOwnerKey,
  privateJson,
  requireViewer,
  verifySameOrigin,
} from "@/lib/security";

export const dynamic = "force-dynamic";

const patchFindingSchema = z.object({
  status: z.enum(["open", "acknowledged", "dismissed"]),
});

export async function PATCH(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const csrf = verifySameOrigin(request);
  if (csrf) return csrf;

  const viewer = await requireViewer(request);
  if (viewer instanceof Response) return viewer;

  const { id } = await context.params;
  const decodedId = decodeURIComponent(id);
  if (!decodedId || decodedId.length > 300) {
    return privateJson({ error: "Invalid finding id" }, 400);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return privateJson({ error: "Invalid JSON body" }, 400);
  }

  const parsed = patchFindingSchema.safeParse(body);
  if (!parsed.success) {
    return privateJson({ error: "Invalid finding status" }, 400);
  }

  try {
    const updated = await updateFindingStatus(
      getViewerOwnerKey(viewer),
      decodedId,
      parsed.data.status,
    );
    if (!updated) {
      return privateJson({ error: "Finding not found" }, 404);
    }
    return privateJson({ updated: true, status: parsed.data.status });
  } catch {
    return privateJson({ error: "Failed to update finding status" }, 500);
  }
}
