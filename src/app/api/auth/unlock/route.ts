import { z } from "zod";
import { getWorkerSecret } from "@/lib/cf-env";
import {
  createAccessKeyCookie,
  PRIVATE_HEADERS,
  privateJson,
  verifyAccessKey,
  verifySameOrigin,
} from "@/lib/security";

export const dynamic = "force-dynamic";

const unlockSchema = z.object({
  passcode: z.string().min(1, "Passcode is required").max(256),
});

export async function POST(request: Request) {
  const csrf = verifySameOrigin(request);
  if (csrf) return csrf;

  const configured = getWorkerSecret("APP_ACCESS_KEY");
  if (!configured) {
    return privateJson({ unlocked: true });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return privateJson({ error: "Invalid JSON body" }, 400);
  }

  const parsed = unlockSchema.safeParse(body);
  if (!parsed.success) {
    return privateJson({ error: "Passcode is required" }, 400);
  }

  const valid = await verifyAccessKey(parsed.data.passcode);
  if (!valid) {
    return privateJson({ error: "Invalid passcode" }, 401);
  }

  const isHttps = request.url.startsWith("https://");
  const cookie = await createAccessKeyCookie(configured, isHttps);
  return Response.json(
    { unlocked: true },
    {
      status: 200,
      headers: {
        ...PRIVATE_HEADERS,
        "set-cookie": cookie,
      },
    },
  );
}
