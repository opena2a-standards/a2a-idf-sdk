import { describe, it, expect } from "vitest";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { level0, level1, level2 } from "../src/levels.js";
import { canonicalizeForSigning, type Attestation } from "../src/attestations.js";

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array =>
  sha512(ed25519.etc.concatBytes(...m));

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const seed = hexToBytes(
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
);
const issuerPub = hexToBytes(
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
);

describe("levels.level0", () => {
  it("returns Level 0 with empty warnings when signature verified", () => {
    const r = level0({ signatureVerified: true });
    expect(r.level).toBe(0);
    expect(r.warnings).toEqual([]);
  });
  it("returns Level 0 with warning when signature failed", () => {
    const r = level0({ signatureVerified: false });
    expect(r.level).toBe(0);
    expect(r.warnings).toContain("signature-verification-failed");
  });
});

describe("levels.level1", () => {
  const baseInputs = {
    signatureVerified: true,
    domain: "acme.example",
    expectedToken: "https://acme.example/keys/agent-1",
    ttlWarnSeconds: 300,
  };

  it("escalates to Level 1 when DNS TXT contains the expected token", async () => {
    const r = await level1({
      ...baseInputs,
      dns: {
        async resolveTxt(name) {
          expect(name).toBe("_a2a-identity.acme.example");
          return {
            records: ["a2a-idf=https://acme.example/keys/agent-1"],
            ttlSeconds: 60,
          };
        },
      },
    });
    expect(r.level).toBe(1);
    expect(r.warnings).toEqual([]);
    expect(r.provenance.dns).toEqual({
      record: "a2a-idf=https://acme.example/keys/agent-1",
      ttlSeconds: 60,
    });
  });

  it("emits a TTL warning when the record TTL exceeds the cap", async () => {
    const r = await level1({
      ...baseInputs,
      dns: {
        async resolveTxt() {
          return {
            records: ["a2a-idf=https://acme.example/keys/agent-1"],
            ttlSeconds: 3600,
          };
        },
      },
    });
    expect(r.level).toBe(1);
    expect(
      r.warnings.some((w) => w.startsWith("dns-ttl-above-cap")),
    ).toBe(true);
  });

  it("falls back to Level 0 when DNS does not advertise the token", async () => {
    const r = await level1({
      ...baseInputs,
      dns: {
        async resolveTxt() {
          return { records: ["v=spf1 -all"], ttlSeconds: 300 };
        },
      },
    });
    expect(r.level).toBe(0);
    expect(r.warnings).toContain("dns-token-not-found");
  });
});

describe("levels.level2", () => {
  it("escalates to Level 2 when a trusted attestation verifies", async () => {
    const trustedIssuer = "https://attestor.example/keys/issuer-1";
    const att: Attestation = {
      issuer: trustedIssuer,
      subject: "https://acme.example/keys/agent-1",
      claim: { type: "organization-binding", org: "Acme Inc." },
      issuedAt: 1_700_000_000,
      expiresAt: 1_700_000_000 + 86400,
      signature: "",
    };
    const sig = ed25519.sign(
      new TextEncoder().encode(canonicalizeForSigning(att)),
      seed,
    );
    att.signature = Buffer.from(sig).toString("base64");

    const r = await level2({
      signatureVerified: true,
      domain: "acme.example",
      expectedToken: "https://acme.example/keys/agent-1",
      ttlWarnSeconds: 300,
      dns: {
        async resolveTxt() {
          return {
            records: ["a2a-idf=https://acme.example/keys/agent-1"],
            ttlSeconds: 60,
          };
        },
      },
      attestationArray: [att],
      attestationOpts: {
        resolveIssuerKey: async (kid) => {
          expect(kid).toBe(trustedIssuer);
          return issuerPub;
        },
        nowSeconds: 1_700_000_001,
      },
      trustedIssuers: new Set([trustedIssuer]),
    });
    expect(r.level).toBe(2);
    expect(r.provenance.attestations).toHaveLength(1);
  });

  it("stays at Level 1 when no attestation issuer is trusted", async () => {
    const r = await level2({
      signatureVerified: true,
      domain: "acme.example",
      expectedToken: "https://acme.example/keys/agent-1",
      ttlWarnSeconds: 300,
      dns: {
        async resolveTxt() {
          return {
            records: ["a2a-idf=https://acme.example/keys/agent-1"],
            ttlSeconds: 60,
          };
        },
      },
      attestationArray: [],
      attestationOpts: {
        resolveIssuerKey: async () => issuerPub,
      },
      trustedIssuers: new Set(["https://other-attestor.example/keys/x"]),
    });
    expect(r.level).toBe(1);
    expect(r.warnings).toContain("no-trusted-attestations");
  });
});
