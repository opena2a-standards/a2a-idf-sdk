import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");
const readme = readFileSync(resolve(repoRoot, "README.md"), "utf-8");

// The vector file test/rfc9421.test.ts byte-matches against.
const vectorsPath = resolve(repoRoot, "vectors/rfc8032-7-1.json");
const fixture: { vectors: { name: string; expectedSignature: string }[] } =
  JSON.parse(readFileSync(vectorsPath, "utf-8"));

// Targets of inline Markdown links: [text](target).
const linkTargets = (markdown: string): string[] =>
  [...markdown.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]!);

const isExternal = (target: string): boolean =>
  /^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith("#");

// Relative link targets resolved to absolute paths, anchors dropped.
const localTargets = (markdown: string): string[] =>
  linkTargets(markdown)
    .filter((t) => !isExternal(t))
    .map((t) => resolve(repoRoot, t.split("#")[0]!));

const section = (markdown: string, heading: string): string => {
  const start = markdown.indexOf(`\n## ${heading}\n`);
  if (start === -1) throw new Error(`README has no "## ${heading}" section`);
  const next = markdown.indexOf("\n## ", start + 1);
  return markdown.slice(start, next === -1 ? undefined : next);
};

describe("README", () => {
  it("links the reference implementation to the AIM repository", () => {
    const line = readme
      .split("\n")
      .find((l) => l.includes("**Reference implementation:**"));
    expect(line).toBeDefined();
    const targets = [...(line ?? "").matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]);
    expect(targets).toEqual(["https://github.com/opena2a-org/agent-identity-management"]);
  });
});

describe("README — relative links", () => {
  it("every relative link target exists in the repository", () => {
    const missing = localTargets(readme).filter((p) => !existsSync(p));
    expect(missing).toEqual([]);
  });
});

describe("README — cross-implementation byte-match section", () => {
  const byteMatch = section(readme, "Cross-implementation byte-match");

  it("links the vendored test vectors", () => {
    expect(localTargets(byteMatch)).toContain(vectorsPath);
  });

  for (const v of fixture.vectors) {
    it(`${v.name}: quotes the vendored expected signature`, () => {
      const base64 = v.expectedSignature.replace(/^sig1=:/, "").replace(/:$/, "");
      expect(byteMatch).toContain(`\`${base64}\``);
    });
  }
});
