// Delegation chain validation per A2A-IDF §5.
//
// A delegation chain is an ordered list of links. The first link is the
// root delegation, signed by the root delegator (an agent). Each subsequent
// link is signed by the previous link's `delegateKeyid` and binds the
// previous link by carrying its signature in `previousSignature`.
//
// Validation rules enforced here:
//   1. First entry payload shape vs subsequent-entry payload shape differ
//      (the first establishes the root; subsequent narrow scope and inherit
//      the previous signature).
//   2. Each link's signature verifies against the *previous* link's
//      `delegateKeyid` resolved public key (for first link: the root key
//      supplied by the caller).
//   3. Scope narrows monotonically. `scope` is an array of opaque strings;
//      every subsequent link's scope MUST be a subset of its predecessor's.
//   4. `expiresAt` is monotonically non-increasing.
//   5. Depth ≤ `maxDepth` (default 4).
//   6. None of the links have expired at `nowSeconds`.

import * as ed25519 from "@noble/ed25519";
import { canonicalize } from "./canonical-json.js";

export interface RootDelegationLink {
  /** First-entry marker. */
  type: "root";
  /** keyid URL of the root delegator (typically a user/operator agent). */
  rootKeyid: string;
  /** keyid URL of the immediate delegate (the next link's signer). */
  delegateKeyid: string;
  /** Set of opaque scope tokens this root permits. */
  scope: string[];
  /** Unix seconds at which this link was issued. */
  issuedAt: number;
  /** Unix seconds after which this link is no longer valid. */
  expiresAt: number;
  /** Ed25519 signature by the root over the canonicalized payload. */
  signature: string;
}

export interface DerivedDelegationLink {
  type: "derived";
  /** Base64 signature of the link this entry extends. Binds the chain. */
  previousSignature: string;
  /** keyid URL of the agent this link delegates to. */
  delegateKeyid: string;
  /** Scope tokens this link permits (MUST be a subset of the previous link's). */
  scope: string[];
  issuedAt: number;
  expiresAt: number;
  /** Ed25519 signature by the previous link's `delegateKeyid` over the canonical payload. */
  signature: string;
}

export type DelegationLink = RootDelegationLink | DerivedDelegationLink;

export interface VerifyDelegationOptions {
  /** Resolves a keyid into the raw 32-byte Ed25519 public key. */
  resolveKey: (keyid: string) => Promise<Uint8Array>;
  /** Wall-clock seconds; defaults to `Date.now()/1000`. */
  nowSeconds?: number;
  /** Max chain length permitted. Defaults to 4. */
  maxDepth?: number;
}

export type DelegationVerifyResult =
  | { ok: true; chain: DelegationLink[]; effectiveScope: string[] }
  | { ok: false; reason: DelegationFailureReason; failedAt: number };

export type DelegationFailureReason =
  | "empty-chain"
  | "depth-exceeded"
  | "first-link-not-root"
  | "subsequent-link-not-derived"
  | "previous-signature-mismatch"
  | "scope-widened"
  | "expiry-widened"
  | "expired"
  | "issued-after-expiry"
  | "key-unresolvable"
  | "signature-invalid"
  | "malformed";

const MAX_DEPTH_DEFAULT = 4;

export async function verifyDelegationChain(
  raw: unknown,
  opts: VerifyDelegationOptions,
): Promise<DelegationVerifyResult> {
  if (!Array.isArray(raw)) {
    return { ok: false, reason: "malformed", failedAt: -1 };
  }
  if (raw.length === 0) {
    return { ok: false, reason: "empty-chain", failedAt: -1 };
  }
  const maxDepth = opts.maxDepth ?? MAX_DEPTH_DEFAULT;
  if (raw.length > maxDepth) {
    return { ok: false, reason: "depth-exceeded", failedAt: maxDepth };
  }
  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);

  const chain: DelegationLink[] = [];

  // First link MUST be a root.
  const firstRaw = raw[0];
  const first = parseRootLink(firstRaw);
  if (first === null) {
    return { ok: false, reason: "first-link-not-root", failedAt: 0 };
  }
  const firstCheck = checkTimeWindow(first, now);
  if (firstCheck !== null) return { ok: false, reason: firstCheck, failedAt: 0 };

  let rootKey: Uint8Array;
  try {
    rootKey = await opts.resolveKey(first.rootKeyid);
  } catch {
    return { ok: false, reason: "key-unresolvable", failedAt: 0 };
  }
  if (!verifySignature(canonicalizeRoot(first), first.signature, rootKey)) {
    return { ok: false, reason: "signature-invalid", failedAt: 0 };
  }
  chain.push(first);

  let prevDelegateKeyid = first.delegateKeyid;
  let prevSignature = first.signature;
  let prevScope = new Set(first.scope);
  let prevExpiresAt = first.expiresAt;

  for (let i = 1; i < raw.length; i++) {
    const link = parseDerivedLink(raw[i]);
    if (link === null) {
      return { ok: false, reason: "subsequent-link-not-derived", failedAt: i };
    }

    if (link.previousSignature !== prevSignature) {
      return { ok: false, reason: "previous-signature-mismatch", failedAt: i };
    }
    for (const tok of link.scope) {
      if (!prevScope.has(tok)) {
        return { ok: false, reason: "scope-widened", failedAt: i };
      }
    }
    if (link.expiresAt > prevExpiresAt) {
      return { ok: false, reason: "expiry-widened", failedAt: i };
    }
    const tw = checkTimeWindow(link, now);
    if (tw !== null) return { ok: false, reason: tw, failedAt: i };

    let signerKey: Uint8Array;
    try {
      signerKey = await opts.resolveKey(prevDelegateKeyid);
    } catch {
      return { ok: false, reason: "key-unresolvable", failedAt: i };
    }
    if (!verifySignature(canonicalizeDerived(link), link.signature, signerKey)) {
      return { ok: false, reason: "signature-invalid", failedAt: i };
    }

    chain.push(link);
    prevDelegateKeyid = link.delegateKeyid;
    prevSignature = link.signature;
    prevScope = new Set(link.scope);
    prevExpiresAt = link.expiresAt;
  }

  return {
    ok: true,
    chain,
    effectiveScope: Array.from(prevScope),
  };
}

// -----------------------------------------------------------------------------
// Parsing.
// -----------------------------------------------------------------------------

function parseRootLink(raw: unknown): RootDelegationLink | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (
    r["type"] !== "root" ||
    typeof r["rootKeyid"] !== "string" ||
    typeof r["delegateKeyid"] !== "string" ||
    !isStringArray(r["scope"]) ||
    typeof r["issuedAt"] !== "number" ||
    typeof r["expiresAt"] !== "number" ||
    typeof r["signature"] !== "string"
  ) {
    return null;
  }
  return {
    type: "root",
    rootKeyid: r["rootKeyid"],
    delegateKeyid: r["delegateKeyid"],
    scope: r["scope"],
    issuedAt: r["issuedAt"],
    expiresAt: r["expiresAt"],
    signature: r["signature"],
  };
}

function parseDerivedLink(raw: unknown): DerivedDelegationLink | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (
    r["type"] !== "derived" ||
    typeof r["previousSignature"] !== "string" ||
    typeof r["delegateKeyid"] !== "string" ||
    !isStringArray(r["scope"]) ||
    typeof r["issuedAt"] !== "number" ||
    typeof r["expiresAt"] !== "number" ||
    typeof r["signature"] !== "string"
  ) {
    return null;
  }
  return {
    type: "derived",
    previousSignature: r["previousSignature"],
    delegateKeyid: r["delegateKeyid"],
    scope: r["scope"],
    issuedAt: r["issuedAt"],
    expiresAt: r["expiresAt"],
    signature: r["signature"],
  };
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

// -----------------------------------------------------------------------------
// Canonical signing inputs (exposed for cross-impl fixture authoring).
// -----------------------------------------------------------------------------

export function canonicalizeRoot(link: RootDelegationLink): string {
  return canonicalize({
    delegateKeyid: link.delegateKeyid,
    expiresAt: link.expiresAt,
    issuedAt: link.issuedAt,
    rootKeyid: link.rootKeyid,
    scope: [...link.scope].sort(),
    type: "root",
  });
}

export function canonicalizeDerived(link: DerivedDelegationLink): string {
  return canonicalize({
    delegateKeyid: link.delegateKeyid,
    expiresAt: link.expiresAt,
    issuedAt: link.issuedAt,
    previousSignature: link.previousSignature,
    scope: [...link.scope].sort(),
    type: "derived",
  });
}

// -----------------------------------------------------------------------------
// Helpers.
// -----------------------------------------------------------------------------

function checkTimeWindow(
  link: DelegationLink,
  now: number,
):
  | null
  | "expired"
  | "issued-after-expiry" {
  if (link.expiresAt <= link.issuedAt) return "issued-after-expiry";
  if (link.expiresAt <= now) return "expired";
  return null;
}

function verifySignature(
  message: string,
  base64Sig: string,
  publicKey: Uint8Array,
): boolean {
  const sig = new Uint8Array(Buffer.from(base64Sig, "base64"));
  return ed25519.verify(sig, new TextEncoder().encode(message), publicKey);
}
