"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";

let lastLiveMessage = "";

function legacyCopy(text: string): boolean {
  const field = Object.assign(document.createElement("textarea"), { value: text });
  field.setAttribute("readonly", "");
  field.style.cssText = "position:fixed;inset-block-start:0;opacity:0";
  document.body.appendChild(field);
  field.select();
  try {
    return document.execCommand("copy");
  } finally {
    field.remove();
  }
}

export function CopyPromptButton({
  targetId,
  label = "Copy Agent Prompt",
  ariaLabel = "Copy agent fix prompt",
}: {
  targetId: string;
  label?: string;
  ariaLabel?: string;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const [announcement, setAnnouncement] = useState("");
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  async function handleCopy() {
    const target = document.getElementById(targetId);
    const text = target ? (target.innerText || target.textContent || "").trim() : "";
    if (!text) return;

    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      ok = legacyCopy(text);
    }

    if (timerRef.current) clearTimeout(timerRef.current);

    let msg = ok ? "Copied" : "Copy failed";
    if (msg === lastLiveMessage) msg += "\u00A0";
    lastLiveMessage = msg;

    setState(ok ? "copied" : "failed");
    setAnnouncement("");
    requestAnimationFrame(() => setAnnouncement(msg));

    timerRef.current = setTimeout(() => {
      setState("idle");
      setAnnouncement("");
    }, 2000);
  }

  return (
    <span className="inline-flex items-center gap-2">
      <button
        type="button"
        onClick={() => void handleCopy()}
        aria-label={ariaLabel}
        data-copied={state === "copied" ? "" : undefined}
        data-failed={state === "failed" ? "" : undefined}
        className="inline-flex min-h-7 min-w-7 items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1 text-xs font-medium text-foreground shadow-xs transition-colors hover:bg-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
      >
        {state === "copied" ? (
          <Check className="size-3.5 text-emerald-500" aria-hidden="true" />
        ) : (
          <Copy className="size-3.5" aria-hidden="true" />
        )}
        <span>{state === "copied" ? "Copied" : state === "failed" ? "Failed" : label}</span>
      </button>
      <span
        role="status"
        className={`text-[11px] transition-opacity duration-150 ${
          announcement ? "opacity-100" : "opacity-0"
        } ${state === "failed" ? "text-destructive" : "text-emerald-600 dark:text-emerald-400"}`}
      >
        {announcement}
      </span>
    </span>
  );
}
