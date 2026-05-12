import { describe, it, expect } from "vitest";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import {
  canonicalizeRoot,
  canonicalizeDerived,
  verifyDelegationChain,
  type RootDelegationLink,
  type DerivedDelegationLink,
} from "../src/delegation.js";

ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array =>
  sha512(ed25519.etc.concatBytes(...m));

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

// Two distinct keypairs so each link is signed by a different actor.
const rootSeed = hexToBytes(
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
);
const rootPub = hexToBytes(
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
);
// RFC 8032 §7.1 Test 2 keypair.
const midSeed = hexToBytes(
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
);
const midPub = hexToBytes(
  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
);

const ROOT_KEYID = "https://opena2a.example/keys/root";
const MID_KEYID = "https://opena2a.example/keys/middle";
const LEAF_KEYID = "https://opena2a.example/keys/leaf";

function signMessage(seed: Uint8Array, message: string): string {
  const sig = ed25519.sign(new TextEncoder().encode(message), seed);
  return Buffer.from(sig).toString("base64");
}

function makeRoot(scope: string[], expiresAt: number): RootDelegationLink {
  const link: RootDelegationLink = {
    type: "root",
    rootKeyid: ROOT_KEYID,
    delegateKeyid: MID_KEYID,
    scope,
    issuedAt: 1_700_000_000,
    expiresAt,
    signature: "",
  };
  link.signature = signMessage(rootSeed, canonicalizeRoot(link));
  return link;
}

function makeDerived(
  prevSig: string,
  scope: string[],
  expiresAt: number,
  delegateKeyid: string = LEAF_KEYID,
  signerSeed: Uint8Array = midSeed,
): DerivedDelegationLink {
  const link: DerivedDelegationLink = {
    type: "derived",
    previousSignature: prevSig,
    delegateKeyid,
    scope,
    issuedAt: 1_700_000_001,
    expiresAt,
    signature: "",
  };
  link.signature = signMessage(signerSeed, canonicalizeDerived(link));
  return link;
}

const keyTable: Record<string, Uint8Array> = {
  [ROOT_KEYID]: rootPub,
  [MID_KEYID]: midPub,
  [LEAF_KEYID]: midPub, // leaf key unused for signature checks (no subsequent link)
};

const resolveKey = async (keyid: string): Promise<Uint8Array> => {
  const k = keyTable[keyid];
  if (k === undefined) throw new Error(`unknown keyid ${keyid}`);
  return k;
};

const now = 1_700_000_500;

describe("delegation.verifyDelegationChain — happy path", () => {
  it("accepts a valid 3-link chain", async () => {
    const root = makeRoot(["task:read", "task:write"], now + 3600);
    const mid = makeDerived(
      root.signature,
      ["task:read", "task:write"],
      now + 1800,
      LEAF_KEYID,
      midSeed,
    );
    // For a 3rd link we'd need a separate leaf signing key. Demonstrate
    // 3 links by reusing the mid key as a deeper delegate.
    const leaf = makeDerived(
      mid.signature,
      ["task:read"],
      now + 600,
      MID_KEYID,
      midSeed,
    );
    // Patch the resolver so the third link's signer is mid's key.
    const r = await verifyDelegationChain([root, mid, leaf], {
      resolveKey,
      nowSeconds: now,
      maxDepth: 4,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.chain).toHaveLength(3);
      expect(r.effectiveScope.sort()).toEqual(["task:read"]);
    }
  });
});

describe("delegation.verifyDelegationChain — rejections", () => {
  it("rejects empty chains", async () => {
    const r = await verifyDelegationChain([], { resolveKey, nowSeconds: now });
    expect(r).toMatchObject({ ok: false, reason: "empty-chain" });
  });

  it("rejects when first link is not a root", async () => {
    const r = await verifyDelegationChain(
      [{ type: "derived", previousSignature: "x", delegateKeyid: "y", scope: [], issuedAt: 0, expiresAt: now + 1, signature: "" }],
      { resolveKey, nowSeconds: now },
    );
    expect(r).toMatchObject({ ok: false, reason: "first-link-not-root" });
  });

  it("rejects tampered previousSignature on second link", async () => {
    const root = makeRoot(["task:read"], now + 3600);
    const mid = makeDerived(root.signature, ["task:read"], now + 1800);
    // Tamper: replace previousSignature with an unrelated value.
    const tampered = {
      ...mid,
      previousSignature: Buffer.from("not-the-root-signature".padEnd(64, "x"))
        .toString("base64"),
    };
    const r = await verifyDelegationChain([root, tampered], {
      resolveKey,
      nowSeconds: now,
    });
    expect(r).toMatchObject({
      ok: false,
      reason: "previous-signature-mismatch",
      failedAt: 1,
    });
  });

  it("rejects scope widening", async () => {
    const root = makeRoot(["task:read"], now + 3600);
    const widened = makeDerived(
      root.signature,
      ["task:read", "task:write"],
      now + 1800,
    );
    const r = await verifyDelegationChain([root, widened], {
      resolveKey,
      nowSeconds: now,
    });
    expect(r).toMatchObject({ ok: false, reason: "scope-widened", failedAt: 1 });
  });

  it("rejects expiry widening", async () => {
    const root = makeRoot(["task:read"], now + 1000);
    const longer = makeDerived(root.signature, ["task:read"], now + 5000);
    const r = await verifyDelegationChain([root, longer], {
      resolveKey,
      nowSeconds: now,
    });
    expect(r).toMatchObject({ ok: false, reason: "expiry-widened", failedAt: 1 });
  });

  it("rejects depth overflow", async () => {
    const root = makeRoot(["task:read"], now + 3600);
    const a = makeDerived(root.signature, ["task:read"], now + 3000);
    const b = makeDerived(a.signature, ["task:read"], now + 2000, MID_KEYID, midSeed);
    const c = makeDerived(b.signature, ["task:read"], now + 1000, MID_KEYID, midSeed);
    const r = await verifyDelegationChain([root, a, b, c], {
      resolveKey,
      nowSeconds: now,
      maxDepth: 3,
    });
    expect(r).toMatchObject({ ok: false, reason: "depth-exceeded" });
  });

  it("rejects expired root link", async () => {
    const root = makeRoot(["task:read"], now - 1);
    const r = await verifyDelegationChain([root], {
      resolveKey,
      nowSeconds: now,
    });
    expect(r).toMatchObject({ ok: false, reason: "expired", failedAt: 0 });
  });
});
