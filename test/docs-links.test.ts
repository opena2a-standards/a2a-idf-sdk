import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  repository: { url: string };
};
const slug = /github\.com[/:]([^/]+\/[^/]+?)(?:\.git)?$/.exec(
  pkg.repository.url,
)?.[1];
if (slug === undefined) {
  throw new Error(
    `package.json repository.url is not a GitHub URL: ${pkg.repository.url}`,
  );
}
const escapedSlug = slug.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A GitHub URL that names a file in this repository on some ref.
const repoUrl = new RegExp(
  `^https://github\\.com/${escapedSlug}/(?:blob|tree|raw)/[^/]+/([^?#]+)`,
  "i",
);

const markdownFiles = [
  "README.md",
  ...readdirSync(join(root, "docs"))
    .filter((f) => f.endsWith(".md"))
    .sort()
    .map((f) => `docs/${f}`),
];

function linkTargets(markdown: string): string[] {
  const prose = markdown.replace(/^```[\s\S]*?^```/gm, "");
  const inline = prose.matchAll(/\]\(\s*<?([^\s)>]+)>?[^)]*\)/g);
  const reference = prose.matchAll(/^ {0,3}\[(?!\^)[^\]]+\]:\s*<?([^\s>]+)/gm);
  return [...inline, ...reference].map((m) => m[1] ?? "");
}

// Repository-relative path a link points at, or null for a link that
// leaves the repository (another site, another repo, an in-page anchor).
function repoPath(file: string, target: string): string | null {
  const inRepo = repoUrl.exec(target);
  if (inRepo) return decodeURIComponent(inRepo[1] ?? "");
  if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(target)) return null;
  const path = decodeURIComponent(target.split(/[?#]/)[0] ?? "");
  return path.startsWith("/")
    ? path.slice(1)
    : posix.join(posix.dirname(file), path);
}

function inRepoLinks(file: string, markdown: string) {
  return linkTargets(markdown).flatMap((target) => {
    const path = repoPath(file, target);
    return path === null ? [] : [{ target, path }];
  });
}

const missingTargets = (links: { target: string; path: string }[]) =>
  links
    .filter(({ path }) => !existsSync(join(root, path)))
    .map(({ target }) => target);

describe("documentation links", () => {
  it("reports a link into this repository whose file is missing", () => {
    const markdown = [
      `see [\`A2A_IDF_CAMPAIGN.md\`](https://github.com/${slug}/blob/main/CAMPAIGN.md) for the trajectory`,
      "- [Contributing](docs/CONTRIBUTING.md)",
      "- [Missing](docs/does-not-exist.md#section)",
      "- [Envoys](https://envoys.me/specs/signature/v1)",
      "- [Status](#status)",
      "",
      "```ts",
      "const x = list[0](arg);",
      "```",
      "",
      "[roadmap]: docs/also-does-not-exist.md",
    ].join("\n");

    const links = inRepoLinks("README.md", markdown);

    expect(links.map(({ path }) => path)).toEqual([
      "CAMPAIGN.md",
      "docs/CONTRIBUTING.md",
      "docs/does-not-exist.md",
      "docs/also-does-not-exist.md",
    ]);
    expect(missingTargets(links)).toEqual([
      `https://github.com/${slug}/blob/main/CAMPAIGN.md`,
      "docs/does-not-exist.md#section",
      "docs/also-does-not-exist.md",
    ]);
  });

  it.each(markdownFiles)(
    "%s links only to files the repository contains",
    (file) => {
      const links = inRepoLinks(file, readFileSync(join(root, file), "utf8"));
      expect(missingTargets(links)).toEqual([]);
    },
  );
});
