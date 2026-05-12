// @opena2a/a2a-idf — reference TypeScript SDK for A2A-IDF (PR #1496).
// Apache 2.0. https://opena2a.org/identity

export {
  sign,
  verify,
  computeContentDigest,
  type SignInputs,
  type SignedHeaders,
  type VerifyInputs,
  type VerifyResult,
  type VerifyFailureReason,
  type SignatureParams,
  type DigestAlgorithm,
} from "./rfc9421.js";

export {
  resolveKeyid,
  type ResolvedKey,
  type ResolveOptions,
} from "./keyid-resolver.js";

export {
  ReplayCache,
  type ReplayCacheOptions,
} from "./replay-cache.js";

export {
  level0,
  level1,
  level2,
  type LevelResult,
  type LevelProvenance,
  type VerificationLevel,
  type DnsResolver,
  type Level0Inputs,
  type Level1Inputs,
  type Level2Inputs,
} from "./levels.js";

export {
  verifyAttestation,
  verifyAttestations,
  canonicalizeForSigning as canonicalizeAttestationForSigning,
  type Attestation,
  type VerifyAttestationOptions,
  type AttestationVerifyResult,
  type AttestationFailureReason,
} from "./attestations.js";

export {
  verifyDelegationChain,
  canonicalizeRoot,
  canonicalizeDerived,
  type DelegationLink,
  type RootDelegationLink,
  type DerivedDelegationLink,
  type VerifyDelegationOptions,
  type DelegationVerifyResult,
  type DelegationFailureReason,
} from "./delegation.js";

export { canonicalize } from "./canonical-json.js";
