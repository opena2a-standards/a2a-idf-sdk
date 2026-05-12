// Attestation array parsing and signature verification per A2A-IDF §1.
//
// An attestation is an Ed25519-signed claim made by one identity (`issuer`)
// about another (`subject`). Verifiers stack attestations to assemble a
// Level 2 verification result.
//
// Payload canonicalization uses RFC 8785 JCS so the same claim shape
// produces the same signing input across implementations.

import * as ed25519 from "@noble/ed25519";
import { canonicalize } from "./canonical-json.js";

export interface Attestation {
  /** keyid URL (the issuer's public-key document). */
  issuer: string;
  /** keyid URL or address the issuer is attesting about. */
  subject: string;
  /** Free-form claim object (e.g., { type: "domain-control", domain: "acme.com" }). */
  claim: Record<string, unknown>;
  /** Unix seconds at which the attestation was issued. */
  issuedAt: number;
  /** Unix seconds after which this attestation is no longer valid. */
  expiresAt: number;
  /** Ed25519 signature, base64 (standard, with padding). */
  signature: string;
}

export interface VerifyAttestationOptions {
  /**
   * Resolver that turns an attestation's `issuer` keyid into a raw 32-byte
   * Ed25519 public key. Typically a thin wrapper around `resolveKeyid`.
   */
  resolveIssuerKey: (issuerKeyid: string) => Promise<Uint8Array>;
  /** Wall-clock seconds; defaults to `Date.now()/1000`. */
  nowSeconds?: number;
}

export type AttestationVerifyResult =
  | { ok: true; attestation: Attestation }
  | { ok: false; reason: AttestationFailureReason; attestation: Attestation };

export type AttestationFailureReason =
  | "expired"
  | "issued-in-future"
  | "issuer-key-unresolvable"
  | "signature-invalid"
  | "malformed";

const SKEW_SECONDS = 60;

export async function verifyAttestation(
  raw: unknown,
  opts: VerifyAttestationOptions,
): Promise<AttestationVerifyResult> {
  const att = parseAttestation(raw);
  if (att === null) {
    return {
      ok: false,
      reason: "malformed",
      attestation: raw as Attestation,
    };
  }

  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (att.expiresAt <= now) {
    return { ok: false, reason: "expired", attestation: att };
  }
  if (att.issuedAt - now > SKEW_SECONDS) {
    return { ok: false, reason: "issued-in-future", attestation: att };
  }

  let issuerKey: Uint8Array;
  try {
    issuerKey = await opts.resolveIssuerKey(att.issuer);
  } catch {
    return { ok: false, reason: "issuer-key-unresolvable", attestation: att };
  }

  const signingInput = new TextEncoder().encode(canonicalizeForSigning(att));
  const sigBytes = new Uint8Array(Buffer.from(att.signature, "base64"));
  const ok = ed25519.verify(sigBytes, signingInput, issuerKey);
  if (!ok) return { ok: false, reason: "signature-invalid", attestation: att };

  return { ok: true, attestation: att };
}

/**
 * Verify every attestation in an array. Returns the subset that passed
 * along with per-failure reasons. Order is preserved; callers can compute
 * Level 2 status by aggregating the passing subset by `claim.type`.
 */
export async function verifyAttestations(
  raw: unknown,
  opts: VerifyAttestationOptions,
): Promise<{
  passing: Attestation[];
  results: AttestationVerifyResult[];
}> {
  if (!Array.isArray(raw)) {
    throw new Error("attestation array must be a JSON array");
  }
  const results: AttestationVerifyResult[] = [];
  const passing: Attestation[] = [];
  for (const entry of raw) {
    const r = await verifyAttestation(entry, opts);
    results.push(r);
    if (r.ok) passing.push(r.attestation);
  }
  return { passing, results };
}

// -----------------------------------------------------------------------------
// Parsing.
// -----------------------------------------------------------------------------

function parseAttestation(raw: unknown): Attestation | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (
    typeof r["issuer"] !== "string" ||
    typeof r["subject"] !== "string" ||
    typeof r["claim"] !== "object" ||
    r["claim"] === null ||
    Array.isArray(r["claim"]) ||
    typeof r["issuedAt"] !== "number" ||
    typeof r["expiresAt"] !== "number" ||
    typeof r["signature"] !== "string"
  ) {
    return null;
  }
  return {
    issuer: r["issuer"],
    subject: r["subject"],
    claim: r["claim"] as Record<string, unknown>,
    issuedAt: r["issuedAt"],
    expiresAt: r["expiresAt"],
    signature: r["signature"],
  };
}

// -----------------------------------------------------------------------------
// Canonical signing input (exposed for cross-impl fixture generation).
// -----------------------------------------------------------------------------

export function canonicalizeForSigning(att: Attestation): string {
  return canonicalize({
    claim: att.claim,
    expiresAt: att.expiresAt,
    issuedAt: att.issuedAt,
    issuer: att.issuer,
    subject: att.subject,
  });
}
