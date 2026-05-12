// RFC 9421 — HTTP Message Signatures, restricted to the components and
// parameters required by A2A-IDF (#1496) and Envoys signature/v1 (#1829).
//
// MVP scope: Ed25519 only, components limited to `@method`, `@path`, and
// `content-digest`. Algorithm agility deferred to v1.x per #1496 §10.2.

import * as ed25519 from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

// Hook @noble/hashes sha512 into @noble/ed25519 so sync APIs work in Node 24.
// Without this, getPublicKey/sign/verify throw "etc.sha512Sync not set".
ed25519.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array =>
  sha512(ed25519.etc.concatBytes(...m));

export type DigestAlgorithm = "sha-256" | "sha-512";

export interface SignatureParams {
  /** Absolute URL resolving to the public key document. RFC 9421 `keyid`. */
  keyid: string;
  /** Unix seconds at which the signature was created. RFC 9421 `created`. */
  created: number;
  /** Opaque per-request token, ≥128 bits entropy. RFC 9421 `nonce`. */
  nonce: string;
  /**
   * Optional signing-purpose tag, per #1496 §6 and lawcontinue's
   * normative request. Distinguishes signatures over the same request
   * shape for different purposes (e.g., "a2a-message", "a2a-resume").
   */
  tag?: string;
}

export interface SignInputs {
  method: string;
  /** Path (and query) portion of the request-target. */
  path: string;
  /** Raw body bytes. Pass an empty Uint8Array for bodyless requests. */
  body: Uint8Array;
  /**
   * Content-Digest algorithm. Defaults to `sha-256`; `sha-512` is
   * accepted per lawcontinue's spec proposal (#1496 §6 follow-up).
   */
  digestAlgorithm?: DigestAlgorithm;
  params: SignatureParams;
  /** Ed25519 raw seed (32 bytes). */
  privateKey: Uint8Array;
}

export interface SignedHeaders {
  /** `sha-256=:<base64>:` or `sha-512=:<base64>:`. */
  "Content-Digest": string;
  /** `sig1=("@method" "@path" "content-digest");keyid=...;created=...;nonce=...` */
  "Signature-Input": string;
  /** `sig1=:<base64>:` */
  Signature: string;
}

export interface VerifyInputs {
  method: string;
  path: string;
  body: Uint8Array;
  headers: {
    "content-digest"?: string;
    "signature-input"?: string;
    signature?: string;
  };
  publicKey: Uint8Array;
  /** Defaults to 300s. Per Envoys §5.2. */
  maxAgeSeconds?: number;
  /** Defaults to 30s. Per Envoys §5.2. */
  maxSkewSeconds?: number;
  /** Wall-clock now, in seconds. Defaults to `Date.now()/1000`. */
  nowSeconds?: number;
  /**
   * Optional replay-protection callback. Receives the parsed nonce; MUST
   * return `false` if previously seen, `true` if first-seen (and record).
   */
  checkNonce?: (nonce: string) => boolean;
}

export type VerifyResult =
  | { ok: true; params: SignatureParams }
  | { ok: false; reason: VerifyFailureReason };

export type VerifyFailureReason =
  | "missing-headers"
  | "missing-signature-input"
  | "missing-signature"
  | "malformed-signature-input"
  | "malformed-signature"
  | "unsupported-component"
  | "content-digest-mismatch"
  | "content-digest-missing"
  | "content-digest-unsupported-algorithm"
  | "timestamp-too-old"
  | "timestamp-future-skew"
  | "replay-detected"
  | "signature-invalid";

// -----------------------------------------------------------------------------
// Base64 (standard, with padding). Matches Envoys §13 output format.
// -----------------------------------------------------------------------------

const b64encode = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64");

const b64decode = (s: string): Uint8Array =>
  new Uint8Array(Buffer.from(s, "base64"));

// -----------------------------------------------------------------------------
// Content-Digest header construction (RFC 9530).
// -----------------------------------------------------------------------------

export function computeContentDigest(
  body: Uint8Array,
  algorithm: DigestAlgorithm = "sha-256",
): string {
  const digest = algorithm === "sha-512" ? sha512(body) : sha256(body);
  return `${algorithm}=:${b64encode(digest)}:`;
}

function parseContentDigestAlgorithm(header: string): DigestAlgorithm | null {
  // RFC 9530 allows multiple digests; we accept the first sha-256 or sha-512.
  if (header.startsWith("sha-256=:")) return "sha-256";
  if (header.startsWith("sha-512=:")) return "sha-512";
  return null;
}

// -----------------------------------------------------------------------------
// Signature-Input parameter serialization (RFC 8941 structured fields, narrowed).
// -----------------------------------------------------------------------------

function serializeParams(params: SignatureParams): string {
  // Order is keyid;created;nonce[;tag] — matches Envoys §4.4 and §13 exactly.
  const parts = [
    `keyid="${params.keyid}"`,
    `created=${params.created}`,
    `nonce="${params.nonce}"`,
  ];
  if (params.tag !== undefined) parts.push(`tag="${params.tag}"`);
  return parts.join(";");
}

function buildSignatureInput(
  components: readonly string[],
  params: SignatureParams,
): string {
  const list = components.map((c) => `"${c}"`).join(" ");
  return `sig1=(${list});${serializeParams(params)}`;
}

// -----------------------------------------------------------------------------
// Signature base (RFC 9421 §2.5).
// -----------------------------------------------------------------------------

function buildSignatureBase(
  method: string,
  path: string,
  contentDigest: string | null,
  components: readonly string[],
  params: SignatureParams,
): string {
  const lines: string[] = [];
  for (const c of components) {
    if (c === "@method") {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (c === "@path") {
      lines.push(`"@path": ${path}`);
    } else if (c === "content-digest") {
      if (contentDigest === null) {
        throw new Error(
          'signature base requires "content-digest" but none was provided',
        );
      }
      lines.push(`"content-digest": ${contentDigest}`);
    } else {
      throw new Error(`unsupported signature component: ${c}`);
    }
  }
  const list = components.map((c) => `"${c}"`).join(" ");
  lines.push(`"@signature-params": (${list});${serializeParams(params)}`);
  return lines.join("\n");
}

// -----------------------------------------------------------------------------
// Public sign() entry point.
// -----------------------------------------------------------------------------

const DEFAULT_COMPONENTS: readonly string[] = [
  "@method",
  "@path",
  "content-digest",
];

export function sign(inputs: SignInputs): SignedHeaders {
  const algorithm: DigestAlgorithm = inputs.digestAlgorithm ?? "sha-256";
  const contentDigest = computeContentDigest(inputs.body, algorithm);
  const base = buildSignatureBase(
    inputs.method,
    inputs.path,
    contentDigest,
    DEFAULT_COMPONENTS,
    inputs.params,
  );
  const signatureBytes = ed25519.sign(
    new TextEncoder().encode(base),
    inputs.privateKey,
  );
  return {
    "Content-Digest": contentDigest,
    "Signature-Input": buildSignatureInput(DEFAULT_COMPONENTS, inputs.params),
    Signature: `sig1=:${b64encode(signatureBytes)}:`,
  };
}

// -----------------------------------------------------------------------------
// Signature-Input parsing.
// -----------------------------------------------------------------------------

interface ParsedSignatureInput {
  components: string[];
  params: SignatureParams;
}

function parseSignatureInput(value: string): ParsedSignatureInput | null {
  // Strictly accept `sig1=(...);keyid=...;created=...;nonce=...[;tag=...]`.
  // Matches the producer above byte-for-byte.
  if (!value.startsWith("sig1=(")) return null;
  const closeIdx = value.indexOf(")", 6);
  if (closeIdx < 0) return null;
  const list = value.slice(6, closeIdx);
  const rest = value.slice(closeIdx + 1);
  if (!rest.startsWith(";")) return null;

  const components: string[] = [];
  for (const token of list.split(" ")) {
    if (!token.startsWith('"') || !token.endsWith('"')) return null;
    components.push(token.slice(1, -1));
  }

  let keyid: string | undefined;
  let created: number | undefined;
  let nonce: string | undefined;
  let tag: string | undefined;
  for (const pair of rest.slice(1).split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) return null;
    const k = pair.slice(0, eq);
    const v = pair.slice(eq + 1);
    if (k === "keyid") {
      if (!v.startsWith('"') || !v.endsWith('"')) return null;
      keyid = v.slice(1, -1);
    } else if (k === "created") {
      const n = Number(v);
      if (!Number.isInteger(n)) return null;
      created = n;
    } else if (k === "nonce") {
      if (!v.startsWith('"') || !v.endsWith('"')) return null;
      nonce = v.slice(1, -1);
    } else if (k === "tag") {
      if (!v.startsWith('"') || !v.endsWith('"')) return null;
      tag = v.slice(1, -1);
    } else {
      // Unknown parameter — reject conservatively. A2A-IDF MVP is strict.
      return null;
    }
  }
  if (keyid === undefined || created === undefined || nonce === undefined) {
    return null;
  }
  return {
    components,
    params: tag === undefined
      ? { keyid, created, nonce }
      : { keyid, created, nonce, tag },
  };
}

function parseSignatureValue(value: string): Uint8Array | null {
  if (!value.startsWith("sig1=:") || !value.endsWith(":")) return null;
  return b64decode(value.slice(6, -1));
}

// -----------------------------------------------------------------------------
// Public verify() entry point.
// -----------------------------------------------------------------------------

export function verify(inputs: VerifyInputs): VerifyResult {
  const sigInputHeader = inputs.headers["signature-input"];
  const sigHeader = inputs.headers.signature;
  const digestHeader = inputs.headers["content-digest"];

  if (sigInputHeader === undefined || sigHeader === undefined) {
    return { ok: false, reason: "missing-headers" };
  }

  const parsed = parseSignatureInput(sigInputHeader);
  if (parsed === null) return { ok: false, reason: "malformed-signature-input" };

  const sigBytes = parseSignatureValue(sigHeader);
  if (sigBytes === null) return { ok: false, reason: "malformed-signature" };

  // Validate components — A2A-IDF MVP rejects anything we can't reconstruct.
  for (const c of parsed.components) {
    if (c !== "@method" && c !== "@path" && c !== "content-digest") {
      return { ok: false, reason: "unsupported-component" };
    }
  }

  // Body integrity, if content-digest is part of the signed components.
  let contentDigestUsed: string | null = null;
  if (parsed.components.includes("content-digest")) {
    if (digestHeader === undefined) {
      return { ok: false, reason: "content-digest-missing" };
    }
    const advertised = parseContentDigestAlgorithm(digestHeader);
    if (advertised === null) {
      return { ok: false, reason: "content-digest-unsupported-algorithm" };
    }
    const recomputed = computeContentDigest(inputs.body, advertised);
    if (recomputed !== digestHeader) {
      return { ok: false, reason: "content-digest-mismatch" };
    }
    contentDigestUsed = digestHeader;
  }

  // Timestamp freshness, per Envoys §5.2 / A2A-IDF default.
  const maxAge = inputs.maxAgeSeconds ?? 300;
  const maxSkew = inputs.maxSkewSeconds ?? 30;
  const now = inputs.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (now - parsed.params.created > maxAge) {
    return { ok: false, reason: "timestamp-too-old" };
  }
  if (parsed.params.created - now > maxSkew) {
    return { ok: false, reason: "timestamp-future-skew" };
  }

  // Replay protection.
  if (inputs.checkNonce !== undefined) {
    if (!inputs.checkNonce(parsed.params.nonce)) {
      return { ok: false, reason: "replay-detected" };
    }
  }

  // Reconstruct the signature base and verify Ed25519.
  const base = buildSignatureBase(
    inputs.method,
    inputs.path,
    contentDigestUsed,
    parsed.components,
    parsed.params,
  );
  const ok = ed25519.verify(
    sigBytes,
    new TextEncoder().encode(base),
    inputs.publicKey,
  );
  if (!ok) return { ok: false, reason: "signature-invalid" };

  return { ok: true, params: parsed.params };
}

// Exposed for advanced consumers and conformance fixtures.
export const _internals = {
  buildSignatureBase,
  buildSignatureInput,
  parseSignatureInput,
  parseSignatureValue,
  serializeParams,
};
