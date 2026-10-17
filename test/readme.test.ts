import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const readme = readFileSync(resolve(__dirname, "../README.md"), "utf-8");

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
