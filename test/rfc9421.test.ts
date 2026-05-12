import { describe, it, expect } from "vitest";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { sign, verify, computeContentDigest } from "../src/rfc9421.js";

// Same etc hook as the library — duplicated here so the test file is
// self-contained when running just this file.
ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array =>
  sha512(ed25519.etc.concatBytes(...m));

interface Vector {
  name: string;
  method: string;
  path: string;
  body: string;
  keyid: string;
  created: number;
  nonce: string;
  expectedContentDigest: string;
  expectedSignatureInput: string;
  expectedSignature: string;
}

interface Fixture {
  keypair: {
    privateKeyHex: string;
    publicKeyRawHex: string;
  };
  vectors: Vector[];
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturePath = resolve(__dirname, "../vectors/rfc8032-7-1.json");
const fixture: Fixture = JSON.parse(readFileSync(fixturePath, "utf-8"));

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const privateKey = hexToBytes(fixture.keypair.privateKeyHex);
const publicKey = hexToBytes(fixture.keypair.publicKeyRawHex);
const bodyOf = (s: string): Uint8Array => new TextEncoder().encode(s);

describe("RFC 9421 sign() — byte-match against Envoys §13 Vectors", () => {
  for (const v of fixture.vectors) {
    it(`${v.name}: signature output equals expected base64 byte-for-byte`, () => {
      const signed = sign({
        method: v.method,
        path: v.path,
        body: bodyOf(v.body),
        params: { keyid: v.keyid, created: v.created, nonce: v.nonce },
        privateKey,
      });
      expect(signed["Content-Digest"]).toBe(v.expectedContentDigest);
      expect(signed["Signature-Input"]).toBe(v.expectedSignatureInput);
      expect(signed.Signature).toBe(v.expectedSignature);
    });
  }
});

describe("RFC 9421 verify() — accepts signatures produced by sign()", () => {
  for (const v of fixture.vectors) {
    it(`${v.name}: verifies with the matching public key`, () => {
      const signed = sign({
        method: v.method,
        path: v.path,
        body: bodyOf(v.body),
        params: { keyid: v.keyid, created: v.created, nonce: v.nonce },
        privateKey,
      });
      const result = verify({
        method: v.method,
        path: v.path,
        body: bodyOf(v.body),
        headers: {
          "content-digest": signed["Content-Digest"],
          "signature-input": signed["Signature-Input"],
          signature: signed.Signature,
        },
        publicKey,
        // Pin the clock — the Envoys vectors use `created=1714*` (April 2024)
        // which is older than any default maxAge.
        nowSeconds: v.created,
      });
      expect(result.ok).toBe(true);
    });
  }
});

describe("RFC 9421 verify() — body-tamper rejection", () => {
  it("rejects when body is altered after signing", () => {
    const v = fixture.vectors[1]!; // POST /api/task with JSON body
    const signed = sign({
      method: v.method,
      path: v.path,
      body: bodyOf(v.body),
      params: { keyid: v.keyid, created: v.created, nonce: v.nonce },
      privateKey,
    });
    const result = verify({
      method: v.method,
      path: v.path,
      body: bodyOf(v.body + " "), // single trailing space alters digest
      headers: {
        "content-digest": signed["Content-Digest"],
        "signature-input": signed["Signature-Input"],
        signature: signed.Signature,
      },
      publicKey,
      nowSeconds: v.created,
    });
    expect(result).toEqual({ ok: false, reason: "content-digest-mismatch" });
  });
});

describe("RFC 9421 computeContentDigest — algorithm dispatch", () => {
  it("defaults to sha-256", () => {
    expect(computeContentDigest(bodyOf(""))).toBe(
      "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    );
  });
  it("accepts sha-512 for ≥4KB body promotion (#1496 §6 follow-up)", () => {
    const digest = computeContentDigest(bodyOf(""), "sha-512");
    expect(digest.startsWith("sha-512=:")).toBe(true);
    expect(digest.endsWith(":")).toBe(true);
  });
});
