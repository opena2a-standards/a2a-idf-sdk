import { describe, it, expect } from "vitest";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import {
  canonicalizeForSigning,
  verifyAttestation,
  verifyAttestations,
  type Attestation,
} from "../src/attestations.js";

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
const pub = hexToBytes(
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
);

function makeAttestation(over: Partial<Attestation> = {}): Attestation {
  const draft: Attestation = {
    issuer: "https://attestor.example/keys/issuer-1",
    subject: "https://acme.example/keys/agent-1",
    claim: { type: "organization-binding", org: "Acme Inc." },
    issuedAt: 1_700_000_000,
    expiresAt: 1_700_000_000 + 86400,
    signature: "",
    ...over,
  };
  const sig = ed25519.sign(
    new TextEncoder().encode(canonicalizeForSigning(draft)),
    seed,
  );
  draft.signature = Buffer.from(sig).toString("base64");
  return draft;
}

describe("attestations.verifyAttestation", () => {
  it("accepts a fresh, well-formed attestation", async () => {
    const att = makeAttestation();
    const r = await verifyAttestation(att, {
      resolveIssuerKey: async () => pub,
      nowSeconds: 1_700_000_001,
    });
    expect(r.ok).toBe(true);
  });

  it("rejects when expired", async () => {
    const att = makeAttestation({ expiresAt: 1_700_000_000 });
    const r = await verifyAttestation(att, {
      resolveIssuerKey: async () => pub,
      nowSeconds: 1_700_000_001,
    });
    expect(r).toMatchObject({ ok: false, reason: "expired" });
  });

  it("rejects when issued in the future beyond the skew tolerance", async () => {
    const att = makeAttestation({
      issuedAt: 1_700_000_000,
      expiresAt: 1_700_000_000 + 86400,
    });
    const r = await verifyAttestation(att, {
      resolveIssuerKey: async () => pub,
      nowSeconds: 1_699_999_800, // 200s before issuedAt
    });
    expect(r).toMatchObject({ ok: false, reason: "issued-in-future" });
  });

  it("rejects when issuer key cannot be resolved", async () => {
    const att = makeAttestation();
    const r = await verifyAttestation(att, {
      resolveIssuerKey: async () => {
        throw new Error("DNS failure");
      },
      nowSeconds: 1_700_000_001,
    });
    expect(r).toMatchObject({ ok: false, reason: "issuer-key-unresolvable" });
  });

  it("rejects when signature is tampered", async () => {
    const att = makeAttestation();
    // Flip one base64 char (avoid '=' / padding boundary).
    const tampered = {
      ...att,
      signature: att.signature.replace(/[A-Z]/, "Z"),
    };
    const r = await verifyAttestation(tampered, {
      resolveIssuerKey: async () => pub,
      nowSeconds: 1_700_000_001,
    });
    expect(r.ok).toBe(false);
  });

  it("rejects malformed payloads", async () => {
    const r = await verifyAttestation(
      { issuer: 42 }, // wrong shape
      { resolveIssuerKey: async () => pub },
    );
    expect(r).toMatchObject({ ok: false, reason: "malformed" });
  });
});

describe("attestations.verifyAttestations", () => {
  it("returns the passing subset and per-entry results", async () => {
    const good = makeAttestation({ claim: { type: "domain-control" } });
    const expired = makeAttestation({
      claim: { type: "domain-control" },
      expiresAt: 1_700_000_000,
    });
    const { passing, results } = await verifyAttestations([good, expired], {
      resolveIssuerKey: async () => pub,
      nowSeconds: 1_700_000_001,
    });
    expect(passing).toHaveLength(1);
    expect(results.map((r) => r.ok)).toEqual([true, false]);
  });
});
