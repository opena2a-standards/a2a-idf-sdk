import { describe, it, expect } from "vitest";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { sign, verify } from "../src/rfc9421.js";
import { ReplayCache } from "../src/replay-cache.js";

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array =>
  sha512(ed25519.etc.concatBytes(...m));

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const privateKey = hexToBytes(
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
);
const publicKey = hexToBytes(
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
);
const bodyOf = (s: string): Uint8Array => new TextEncoder().encode(s);

function signFresh(created: number, nonce: string) {
  return sign({
    method: "POST",
    path: "/api/task",
    body: bodyOf("{}"),
    params: {
      keyid: "https://opena2a.example/agents/test",
      created,
      nonce,
    },
    privateKey,
  });
}

describe("RFC 9421 verify() — replay protection", () => {
  it("rejects when created is older than maxAge (default 300s)", () => {
    const signedAt = 1_000_000;
    const headers = signFresh(signedAt, "nonceA0123456789012345");
    const result = verify({
      method: "POST",
      path: "/api/task",
      body: bodyOf("{}"),
      headers: {
        "content-digest": headers["Content-Digest"],
        "signature-input": headers["Signature-Input"],
        signature: headers.Signature,
      },
      publicKey,
      nowSeconds: signedAt + 301,
    });
    expect(result).toEqual({ ok: false, reason: "timestamp-too-old" });
  });

  it("rejects when created is too far in the future (default skew 30s)", () => {
    const signedAt = 1_000_000;
    const headers = signFresh(signedAt, "nonceB0123456789012345");
    const result = verify({
      method: "POST",
      path: "/api/task",
      body: bodyOf("{}"),
      headers: {
        "content-digest": headers["Content-Digest"],
        "signature-input": headers["Signature-Input"],
        signature: headers.Signature,
      },
      publicKey,
      nowSeconds: signedAt - 31,
    });
    expect(result).toEqual({ ok: false, reason: "timestamp-future-skew" });
  });

  it("rejects on previously-seen nonce via ReplayCache", () => {
    const signedAt = 1_000_000;
    const headers = signFresh(signedAt, "nonceC0123456789012345");
    const cache = new ReplayCache({ now: () => signedAt });
    const check = cache.check.bind(cache);

    const first = verify({
      method: "POST",
      path: "/api/task",
      body: bodyOf("{}"),
      headers: {
        "content-digest": headers["Content-Digest"],
        "signature-input": headers["Signature-Input"],
        signature: headers.Signature,
      },
      publicKey,
      nowSeconds: signedAt,
      checkNonce: check,
    });
    expect(first.ok).toBe(true);

    const second = verify({
      method: "POST",
      path: "/api/task",
      body: bodyOf("{}"),
      headers: {
        "content-digest": headers["Content-Digest"],
        "signature-input": headers["Signature-Input"],
        signature: headers.Signature,
      },
      publicKey,
      nowSeconds: signedAt,
      checkNonce: check,
    });
    expect(second).toEqual({ ok: false, reason: "replay-detected" });
  });

  it("evicts entries after TTL expires", () => {
    let t = 1_000_000;
    const cache = new ReplayCache({ ttlSeconds: 60, now: () => t });
    expect(cache.check("n1")).toBe(true);
    expect(cache.check("n1")).toBe(false);
    t += 61;
    expect(cache.check("n1")).toBe(true);
  });

  it("respects capacity by evicting oldest entry", () => {
    const t = 1_000_000;
    const cache = new ReplayCache({ capacity: 2, ttlSeconds: 10_000, now: () => t });
    cache.check("a"); // {a}
    cache.check("b"); // {a, b}
    cache.check("c"); // capacity hit → evict oldest ("a") → {b, c}
    // "a" was evicted, so it's first-seen again:
    expect(cache.check("a")).toBe(true);
    // "c" was never evicted — still seen:
    // (state at this point is {c, a}; b was the next-oldest and just got evicted to fit "a")
    expect(cache.check("c")).toBe(false);
  });
});
