import type { DependencyItem, RuntimeSignal } from "./types";

const MAX_DEPS_PER_REPO = 250;

export function cleanSemver(raw: string): string {
  return raw
    .trim()
    .replace(/^[~^=<>v\s]+/, "")
    .replace(/[\s,].*$/, "")
    .trim();
}

/**
 * Compares two loose dotted version strings (e.g. "14.2.15" vs "14.2.25").
 * Returns -1 if a < b, 0 if equal, 1 if a > b, or null if non-numeric.
 */
export function compareVersions(a: string, b: string): number | null {
  const cleanA = cleanSemver(a).split("-")[0];
  const cleanB = cleanSemver(b).split("-")[0];
  if (!/^\d+(\.\d+)*$/.test(cleanA) || !/^\d+(\.\d+)*$/.test(cleanB)) {
    return null;
  }
  const partsA = cleanA.split(".").map((n) => Number.parseInt(n, 10));
  const partsB = cleanB.split(".").map((n) => Number.parseInt(n, 10));
  const len = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < len; i++) {
    const numA = partsA[i] ?? 0;
    const numB = partsB[i] ?? 0;
    if (numA < numB) return -1;
    if (numA > numB) return 1;
  }
  return 0;
}

export function isExactVersion(raw: string): boolean {
  const trimmed = raw.trim();
  return /^v?\d+\.\d+(\.\d+)?([-.][0-9A-Za-z.]+)?$/.test(trimmed);
}

export function parsePackageJson(
  content: string,
  manifestPath: string,
): { deps: DependencyItem[]; runtimes: RuntimeSignal[]; frameworks: string[] } {
  const deps: DependencyItem[] = [];
  const runtimes: RuntimeSignal[] = [];
  const frameworks = new Set<string>();

  try {
    const parsed = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      engines?: Record<string, string>;
    };

    const allDeps: Record<string, string> = {
      ...(parsed.dependencies ?? {}),
      ...(parsed.devDependencies ?? {}),
    };

    for (const [name, version] of Object.entries(allDeps)) {
      if (typeof version !== "string") continue;
      deps.push({
        name,
        version: cleanSemver(version) || version,
        ecosystem: "npm",
        manifestPath,
        direct: true,
      });

      if (name === "next") frameworks.add("Next.js");
      if (name === "react") frameworks.add("React");
      if (name === "express") frameworks.add("Express");
      if (name === "hono") frameworks.add("Hono");
      if (name === "astro") frameworks.add("Astro");
      if (name === "vue" || name === "nuxt") frameworks.add("Vue / Nuxt");
      if (name === "svelte" || name === "@sveltejs/kit") frameworks.add("SvelteKit");
      if (name === "expo" || name === "react-native") frameworks.add("React Native / Expo");
      if (name === "wrangler" || name === "@cloudflare/workers-types") {
        frameworks.add("Cloudflare Workers");
      }
      if (name === "@nestjs/core") frameworks.add("NestJS");
      if (name === "tailwindcss") frameworks.add("Tailwind CSS");
    }

    if (parsed.engines?.node) {
      runtimes.push({
        runtime: "Node.js",
        version: parsed.engines.node,
        pinned: isExactVersion(parsed.engines.node),
        sourceFile: manifestPath,
      });
    }
  } catch {
    // Ignore malformed JSON
  }

  return {
    deps: deps.slice(0, MAX_DEPS_PER_REPO),
    runtimes,
    frameworks: [...frameworks],
  };
}

export function parsePackageLockJson(
  content: string,
  manifestPath: string,
): DependencyItem[] {
  const map = new Map<string, DependencyItem>();
  try {
    const parsed = JSON.parse(content) as {
      packages?: Record<string, { version?: string }>;
      dependencies?: Record<string, { version?: string }>;
    };

    if (parsed.packages) {
      for (const [pkgPath, meta] of Object.entries(parsed.packages)) {
        if (!pkgPath || !meta?.version) continue;
        const segments = pkgPath.split("node_modules/");
        const name = segments[segments.length - 1];
        if (!name || name.startsWith(".")) continue;
        if (!map.has(name)) {
          map.set(name, {
            name,
            version: cleanSemver(meta.version),
            ecosystem: "npm",
            manifestPath,
            direct: segments.length === 2,
          });
        }
        if (map.size >= MAX_DEPS_PER_REPO) break;
      }
    } else if (parsed.dependencies) {
      for (const [name, meta] of Object.entries(parsed.dependencies)) {
        if (!meta?.version) continue;
        map.set(name, {
          name,
          version: cleanSemver(meta.version),
          ecosystem: "npm",
          manifestPath,
          direct: true,
        });
        if (map.size >= MAX_DEPS_PER_REPO) break;
      }
    }
  } catch {
    // Ignore malformed lockfile
  }
  return [...map.values()];
}

export function parseComposerJson(
  content: string,
  manifestPath: string,
): { deps: DependencyItem[]; runtimes: RuntimeSignal[]; frameworks: string[] } {
  const deps: DependencyItem[] = [];
  const runtimes: RuntimeSignal[] = [];
  const frameworks = new Set<string>(["PHP"]);

  try {
    const parsed = JSON.parse(content) as {
      require?: Record<string, string>;
      "require-dev"?: Record<string, string>;
    };
    const combined = { ...(parsed.require ?? {}), ...(parsed["require-dev"] ?? {}) };

    for (const [name, version] of Object.entries(combined)) {
      if (typeof version !== "string") continue;
      if (name === "php") {
        runtimes.push({
          runtime: "PHP",
          version,
          pinned: isExactVersion(version),
          sourceFile: manifestPath,
        });
        continue;
      }
      if (name.startsWith("ext-")) continue;
      deps.push({
        name,
        version: cleanSemver(version) || version,
        ecosystem: "Packagist",
        manifestPath,
        direct: true,
      });

      if (name.startsWith("laravel/")) frameworks.add("Laravel");
      if (name.startsWith("symfony/")) frameworks.add("Symfony");
      if (name.includes("wordpress")) frameworks.add("WordPress");
    }
  } catch {
    // Ignore malformed JSON
  }

  return {
    deps: deps.slice(0, MAX_DEPS_PER_REPO),
    runtimes,
    frameworks: [...frameworks],
  };
}

export function parseComposerLock(content: string, manifestPath: string): DependencyItem[] {
  const deps: DependencyItem[] = [];
  try {
    const parsed = JSON.parse(content) as {
      packages?: Array<{ name?: string; version?: string }>;
      "packages-dev"?: Array<{ name?: string; version?: string }>;
    };
    const all = [...(parsed.packages ?? []), ...(parsed["packages-dev"] ?? [])];
    for (const pkg of all) {
      if (!pkg.name || !pkg.version) continue;
      deps.push({
        name: pkg.name,
        version: cleanSemver(pkg.version),
        ecosystem: "Packagist",
        manifestPath,
      });
      if (deps.length >= MAX_DEPS_PER_REPO) break;
    }
  } catch {
    // Ignore malformed lockfile
  }
  return deps;
}

export function parseRequirementsTxt(
  content: string,
  manifestPath: string,
): { deps: DependencyItem[]; frameworks: string[] } {
  const deps: DependencyItem[] = [];
  const frameworks = new Set<string>();

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const match = line.match(/^([A-Za-z0-9._-]+)(?:\[.*?\])?\s*(?:===|==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9.*+-]+)?/);
    if (!match) continue;
    const name = match[1].toLowerCase();
    const version = match[2] ? cleanSemver(match[2]) : "unpinned";
    deps.push({
      name,
      version,
      ecosystem: "PyPI",
      manifestPath,
      direct: true,
    });

    if (name === "fastapi") frameworks.add("FastAPI");
    if (name === "django") frameworks.add("Django");
    if (name === "flask") frameworks.add("Flask");
    if (name === "starlette") frameworks.add("Starlette");
    if (deps.length >= MAX_DEPS_PER_REPO) break;
  }

  return { deps, frameworks: [...frameworks] };
}

export function parsePyprojectToml(
  content: string,
  manifestPath: string,
): { deps: DependencyItem[]; runtimes: RuntimeSignal[]; frameworks: string[] } {
  const deps: DependencyItem[] = [];
  const runtimes: RuntimeSignal[] = [];
  const frameworks = new Set<string>();

  const pyVersionMatch = content.match(/requires-python\s*=\s*["']([^"']+)["']/);
  if (pyVersionMatch) {
    runtimes.push({
      runtime: "Python",
      version: pyVersionMatch[1],
      pinned: isExactVersion(pyVersionMatch[1]),
      sourceFile: manifestPath,
    });
  }

  const depMatches = content.matchAll(/["']([A-Za-z0-9._-]+)(?:\[.*?\])?\s*(?:==|>=|<=|~=|!=)\s*([0-9][A-Za-z0-9.*+-]*)["']/g);
  for (const m of depMatches) {
    const name = m[1].toLowerCase();
    const version = cleanSemver(m[2]);
    deps.push({
      name,
      version,
      ecosystem: "PyPI",
      manifestPath,
      direct: true,
    });
    if (name === "fastapi") frameworks.add("FastAPI");
    if (name === "django") frameworks.add("Django");
    if (name === "flask") frameworks.add("Flask");
    if (deps.length >= MAX_DEPS_PER_REPO) break;
  }

  return { deps, runtimes, frameworks: [...frameworks] };
}

export function parseGoMod(
  content: string,
  manifestPath: string,
): { deps: DependencyItem[]; runtimes: RuntimeSignal[] } {
  const deps: DependencyItem[] = [];
  const runtimes: RuntimeSignal[] = [];

  const goMatch = content.match(/^go\s+([0-9.]+)/m);
  if (goMatch) {
    runtimes.push({
      runtime: "Go",
      version: goMatch[1],
      pinned: true,
      sourceFile: manifestPath,
    });
  }

  const lineMatches = content.matchAll(/^\s*([a-zA-Z0-9._/-]+\.[a-zA-Z0-9._/-]+)\s+(v[0-9][^\s]*)/gm);
  for (const m of lineMatches) {
    deps.push({
      name: m[1],
      version: cleanSemver(m[2]),
      ecosystem: "Go",
      manifestPath,
      direct: true,
    });
    if (deps.length >= MAX_DEPS_PER_REPO) break;
  }

  return { deps, runtimes };
}

export function parseDockerfile(
  content: string,
  manifestPath: string,
): { dockerImages: string[]; runtimes: RuntimeSignal[] } {
  const dockerImages: string[] = [];
  const runtimes: RuntimeSignal[] = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const match = line.match(/^FROM\s+(?:--platform=\S+\s+)?([^\s]+)/i);
    if (!match) continue;
    const image = match[1];
    dockerImages.push(image);

    const lower = image.toLowerCase();
    if (lower.startsWith("php:")) {
      runtimes.push({
        runtime: "PHP",
        version: image.slice(4),
        pinned: /\d+\.\d+/.test(image),
        sourceFile: manifestPath,
      });
    } else if (lower.startsWith("node:")) {
      runtimes.push({
        runtime: "Node.js",
        version: image.slice(5),
        pinned: /\d+/.test(image),
        sourceFile: manifestPath,
      });
    } else if (lower.startsWith("python:")) {
      runtimes.push({
        runtime: "Python",
        version: image.slice(7),
        pinned: /\d+\.\d+/.test(image),
        sourceFile: manifestPath,
      });
    } else if (lower.startsWith("golang:")) {
      runtimes.push({
        runtime: "Go",
        version: image.slice(7),
        pinned: /\d+\.\d+/.test(image),
        sourceFile: manifestPath,
      });
    }
  }

  return { dockerImages, runtimes };
}

export function mergeDependencies(
  lockfileDeps: DependencyItem[],
  manifestDeps: DependencyItem[],
): DependencyItem[] {
  const map = new Map<string, DependencyItem>();
  // Prefer lockfile exact versions first
  for (const dep of lockfileDeps) {
    const key = `${dep.ecosystem}:${dep.name.toLowerCase()}`;
    if (!map.has(key)) {
      map.set(key, dep);
    }
  }
  for (const dep of manifestDeps) {
    const key = `${dep.ecosystem}:${dep.name.toLowerCase()}`;
    if (!map.has(key)) {
      map.set(key, dep);
    }
  }
  return [...map.values()].slice(0, MAX_DEPS_PER_REPO);
}
