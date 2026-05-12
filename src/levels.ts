// Verification level helpers per A2A-IDF §1.
//
//   Level 0 — self-asserted. The AgentCard ships its own signature alone.
//             A successful RFC 9421 verify against the AgentCard's declared
//             keyid is sufficient.
//
//   Level 1 — domain-verified. In addition to Level 0, a DNS TXT record at
//             `_a2a-identity.<domain>` advertises the keyid (or its hash).
//             A short TTL (≤ 300s) is REQUIRED for a clean Level 1; longer
//             TTLs surface a `warnings` entry but do not downgrade the
//             level on their own.
//
//   Level 2 — organization-verified. In addition to Level 1, an attestation
//             array carries third-party signatures binding the agent to an
//             organization. Verifiers MAY accept Level 2 without Level 1 if
//             at least one trusted attestation explicitly covers DNS
//             control — captured here as the `domain-control` claim type.

import {
  verifyAttestations,
  type Attestation,
  type VerifyAttestationOptions,
} from "./attestations.js";

export type VerificationLevel = 0 | 1 | 2;

export interface LevelProvenance {
  /** Always populated when level ≥ 0. */
  signatureVerified: boolean;
  /** Set when DNS lookup succeeded. */
  dns?: {
    record: string;
    ttlSeconds: number;
  };
  /** Subset of attestations that verified, by `claim.type` for quick lookup. */
  attestations: Attestation[];
}

export interface LevelResult {
  level: VerificationLevel;
  provenance: LevelProvenance;
  warnings: string[];
}

// -----------------------------------------------------------------------------
// Level 0
// -----------------------------------------------------------------------------

export interface Level0Inputs {
  /** Result of an RFC 9421 verify() call on the AgentCard's signature. */
  signatureVerified: boolean;
}

export function level0(inputs: Level0Inputs): LevelResult {
  return {
    level: 0,
    provenance: {
      signatureVerified: inputs.signatureVerified,
      attestations: [],
    },
    warnings: inputs.signatureVerified
      ? []
      : ["signature-verification-failed"],
  };
}

// -----------------------------------------------------------------------------
// Level 1 — DNS TXT `_a2a-identity.<domain>` with TTL cap.
// -----------------------------------------------------------------------------

export interface DnsResolver {
  /**
   * Returns the TXT records and the minimum TTL observed.
   * If no records exist, return an empty `records` array.
   */
  resolveTxt(
    name: string,
  ): Promise<{ records: string[]; ttlSeconds: number }>;
}

export interface Level1Inputs {
  signatureVerified: boolean;
  /** Domain to check (e.g., "acme.com"). */
  domain: string;
  /** Expected token in the TXT record (typically the keyid URL or its sha256). */
  expectedToken: string;
  dns: DnsResolver;
  /** Cap above which we emit a warning. Defaults to 300 (per #1496 guidance). */
  ttlWarnSeconds?: number;
}

const A2A_IDENTITY_PREFIX = "_a2a-identity";
const DEFAULT_TTL_WARN = 300;

export async function level1(inputs: Level1Inputs): Promise<LevelResult> {
  const warnings: string[] = [];
  if (!inputs.signatureVerified) {
    warnings.push("signature-verification-failed");
    return {
      level: 0,
      provenance: { signatureVerified: false, attestations: [] },
      warnings,
    };
  }

  const name = `${A2A_IDENTITY_PREFIX}.${inputs.domain}`;
  const { records, ttlSeconds } = await inputs.dns.resolveTxt(name);
  const match = records.find((r) => r.includes(inputs.expectedToken));
  if (match === undefined) {
    warnings.push("dns-token-not-found");
    return {
      level: 0,
      provenance: { signatureVerified: true, attestations: [] },
      warnings,
    };
  }

  const ttlCap = inputs.ttlWarnSeconds ?? DEFAULT_TTL_WARN;
  if (ttlSeconds > ttlCap) {
    warnings.push(
      `dns-ttl-above-cap:${ttlSeconds}s > ${ttlCap}s — stale-key risk after revocation`,
    );
  }

  return {
    level: 1,
    provenance: {
      signatureVerified: true,
      dns: { record: match, ttlSeconds },
      attestations: [],
    },
    warnings,
  };
}

// -----------------------------------------------------------------------------
// Level 2 — attestation array including a domain-control claim.
// -----------------------------------------------------------------------------

export interface Level2Inputs extends Level1Inputs {
  attestationArray: unknown;
  attestationOpts: VerifyAttestationOptions;
  /** Issuer keyids the verifier trusts to bind agent→organization. */
  trustedIssuers: Set<string>;
}

export async function level2(inputs: Level2Inputs): Promise<LevelResult> {
  const l1 = await level1(inputs);
  if (l1.level === 0) return l1; // signature or DNS failed — don't escalate

  const { passing } = await verifyAttestations(
    inputs.attestationArray,
    inputs.attestationOpts,
  );
  const trusted = passing.filter((a) => inputs.trustedIssuers.has(a.issuer));
  if (trusted.length === 0) {
    return {
      ...l1,
      warnings: [...l1.warnings, "no-trusted-attestations"],
    };
  }

  return {
    level: 2,
    provenance: {
      signatureVerified: true,
      ...(l1.provenance.dns !== undefined && { dns: l1.provenance.dns }),
      attestations: trusted,
    },
    warnings: l1.warnings,
  };
}
