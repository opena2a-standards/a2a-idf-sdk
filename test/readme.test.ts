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
  // A line may name a reference implementation only if the same line cites a
  // conformance run: a2a-idf-conformance, then a release tag, then
  // "(commit <sha>)". The suite name may be a link, and the tag and the sha may
  // be in backticks. An unfilled placeholder such as {tag} or {sha} is not a
  // citation.
  const namesReferenceImplementation = (line: string): boolean =>
    /\breference[\s-]+implementations?\b/i.test(line);

  const citesConformanceRun = (line: string): boolean =>
    /a2a-idf-conformance\S*\s+`?v?\d+(?:\.\d+){1,2}(?:-[0-9A-Za-z.]+)?`?\s+\(commit\s+`?[0-9a-f]{7,40}`?\)/.test(
      line,
    );

  const referenceLines = (markdown: string): string[] =>
    markdown.split("\n").filter(namesReferenceImplementation);

  const uncitedReferenceLines = (markdown: string): string[] =>
    referenceLines(markdown).filter((l) => !citesConformanceRun(l));

  it("names a reference implementation only on a line that cites a conformance run with a tag and a commit, and names none today", () => {
    expect(uncitedReferenceLines(readme)).toEqual([]);
    // No README line names one today. The change that adds a line citing a
    // conformance run updates this expectation with it.
    expect(referenceLines(readme)).toEqual([]);
  });

  const aim =
    "- **Reference implementation:** [AIM](https://github.com/opena2a-org/agent-identity-management)";
  const sha = "0123456789abcdef0123456789abcdef01234567";

  const uncited: [string, string][] = [
    ["no conformance run", aim],
    [
      "the placeholders left unfilled",
      `${aim}: passes a2a-idf-conformance {tag} (commit {sha}) as a required check, {date}.`,
    ],
    ["a tag and no commit", `${aim}: passes a2a-idf-conformance v0.1.0 as a required check, 2026-11-13.`],
    ["a commit and no tag", `${aim}: passes a2a-idf-conformance (commit ${sha}) as a required check, 2026-11-13.`],
  ];

  for (const [name, line] of uncited) {
    it(`rejects a reference-implementation line with ${name}`, () => {
      expect(uncitedReferenceLines(line)).toEqual([line]);
    });
  }

  it("rejects a reference-implementation line whose conformance run is cited on the next line", () => {
    const markdown = `${aim}\n  passes a2a-idf-conformance v0.1.0 (commit ${sha}) as a required check, 2026-11-13.`;
    expect(uncitedReferenceLines(markdown)).toEqual([aim]);
  });

  it("accepts a reference-implementation line that cites a2a-idf-conformance with a tag and a commit", () => {
    const line = `${aim}: passes a2a-idf-conformance v0.1.0 (commit ${sha}) as a required check, 2026-11-13.`;
    expect(referenceLines(line)).toEqual([line]);
    expect(uncitedReferenceLines(line)).toEqual([]);
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
