import { z } from "zod";
import { runAndSaveAdvisoryCheck } from "@/lib/fleet-service";
import {
  getViewerOwnerKey,
  privateJson,
  requireViewer,
  verifySameOrigin,
} from "@/lib/security";

export const dynamic = "force-dynamic";

const advisoryCheckSchema = z.object({
  query: z.string().trim().min(2, "Enter a CVE, advisory URL, or description").max(600),
  runStage2: z.boolean().optional().default(true),
});

export async function POST(request: Request) {
  const csrf = verifySameOrigin(request);
  if (csrf) return csrf;

  const viewer = await requireViewer(request);
  if (viewer instanceof Response) return viewer;

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return privateJson({ error: "Invalid JSON body" }, 400);
  }

  const parsed = advisoryCheckSchema.safeParse(body);
  if (!parsed.success) {
    return privateJson(
      { error: parsed.error.issues[0]?.message ?? "Invalid advisory check request" },
      400,
    );
  }

  try {
    const ownerSub = getViewerOwnerKey(viewer);
    const check = await runAndSaveAdvisoryCheck(
      ownerSub,
      parsed.data.query,
      parsed.data.runStage2,
    );
    return privateJson({ check }, 201);
  } catch {
    return privateJson({ error: "Advisory check failed. Please retry." }, 500);
  }
}
