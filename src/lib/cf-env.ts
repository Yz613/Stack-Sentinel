import { env } from "cloudflare:workers";

export interface StackSentinelEnv extends Cloudflare.Env {
  GITHUB_TOKEN?: string;
  APP_ACCESS_KEY?: string;
}

export function getWorkerEnv(): StackSentinelEnv {
  return env as StackSentinelEnv;
}

export function getWorkerSecret(name: "GITHUB_TOKEN" | "APP_ACCESS_KEY"): string {
  const workerEnv = getWorkerEnv();
  const fromBinding = workerEnv?.[name];
  if (typeof fromBinding === "string" && fromBinding.trim() !== "") {
    return fromBinding.trim();
  }
  const fromProcess =
    typeof process !== "undefined" ? process.env?.[name] : undefined;
  return typeof fromProcess === "string" ? fromProcess.trim() : "";
}
