import { getWorkerSecret } from "./cf-env";

export const PRIVATE_HEADERS = {
  "cache-control": "private, no-store",
} as const;

export const SESSION_COOKIE_NAME = "stack_sentinel_session";
const SESSION_PAYLOAD = "stack-sentinel:v1";

export interface AppViewer {
  sub: string;
  name: string;
  email: string;
  authMode: "cloudflare_access" | "access_key" | "open";
}

export function privateJson(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: PRIVATE_HEADERS,
  });
}

function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

async function computeSessionMac(secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(SESSION_PAYLOAD));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function createAccessKeyCookie(
  secret: string,
  isSecure: boolean,
): Promise<string> {
  const mac = await computeSessionMac(secret);
  const parts = [
    `${SESSION_COOKIE_NAME}=${mac}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=604800",
  ];
  if (isSecure) parts.push("Secure");
  return parts.join("; ");
}

export async function verifyAccessKey(candidate: string): Promise<boolean> {
  const expected = getWorkerSecret("APP_ACCESS_KEY");
  if (!expected) return true;
  const [a, b] = await Promise.all([
    computeSessionMac(candidate),
    computeSessionMac(expected),
  ]);
  return timingSafeEqualStr(a, b);
}

/**
 * Resolves the caller identity on Cloudflare Workers:
 * 1. Cloudflare Access header (`Cf-Access-Authenticated-User-Email`) when behind Zero Trust.
 * 2. Optional `APP_ACCESS_KEY` passcode cookie / header when configured as a Worker secret.
 * 3. Default workspace viewer when running an open preview.
 */
export async function requireViewer(request: Request): Promise<AppViewer | Response> {
  const cfAccessEmail = request.headers.get("cf-access-authenticated-user-email")?.trim();
  if (cfAccessEmail) {
    return {
      sub: `cf-access:${cfAccessEmail.toLowerCase()}`,
      name: cfAccessEmail.split("@")[0] || "Cloudflare Access User",
      email: cfAccessEmail,
      authMode: "cloudflare_access",
    };
  }

  const accessKey = getWorkerSecret("APP_ACCESS_KEY");
  if (accessKey) {
    const cookies = parseCookies(request.headers.get("cookie"));
    const expectedMac = await computeSessionMac(accessKey);
    const cookieMac = cookies[SESSION_COOKIE_NAME] ?? "";
    const headerKey = request.headers.get("x-access-key")?.trim() ?? "";

    const cookieValid = cookieMac !== "" && timingSafeEqualStr(cookieMac, expectedMac);
    const headerValid = headerKey !== "" && (await verifyAccessKey(headerKey));

    if (!cookieValid && !headerValid) {
      return privateJson(
        { error: "Access passcode required", authRequired: true },
        401,
      );
    }

    return {
      sub: "workspace:owner",
      name: "Authorized Owner",
      email: "",
      authMode: "access_key",
    };
  }

  return {
    sub: "workspace:default",
    name: "Workspace",
    email: "",
    authMode: "open",
  };
}

export function verifySameOrigin(request: Request): Response | null {
  const origin = request.headers.get("origin");
  if (!origin) return null;

  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  if (!host) return null;

  try {
    const parsedOrigin = new URL(origin);
    if (parsedOrigin.host !== host) {
      return privateJson({ error: "Cross-origin state-changing request rejected" }, 403);
    }
  } catch {
    return privateJson({ error: "Invalid Origin header" }, 403);
  }
  return null;
}

export function safeExternalUrl(rawUrl: string | undefined | null): string {
  if (!rawUrl) return "";
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === "https:") {
      return parsed.toString();
    }
    return "";
  } catch {
    return "";
  }
}

export function getViewerOwnerKey(viewer: AppViewer): string {
  return viewer.sub;
}

export function getViewerDisplay(viewer: AppViewer): {
  name: string;
  email: string;
  authMode: "cloudflare_access" | "access_key" | "open";
} {
  return {
    name: viewer.name,
    email: viewer.email,
    authMode: viewer.authMode,
  };
}
