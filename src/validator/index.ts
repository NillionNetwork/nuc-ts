import * as did from "#/core/did/did";
import { Log } from "#/core/logger";
import type { Envelope } from "#/nuc/envelope";
import {
  getProofBytes,
  isDelegationPayload,
  isInvocationPayload,
  type Payload,
} from "#/nuc/payload";
import { evaluatePolicy } from "#/nuc/policy";
import {
  CHAIN_TOO_LONG,
  PROOFS_MUST_BE_DELEGATIONS,
  sortProofs,
  TOO_MANY_PROOFS,
  validatePayloadChain,
  validateProofs,
} from "./chain";
import { INVALID_SIGNATURES, validateEnvelopeSignatures } from "./signatures";
import type {
  TokenRequirement,
  ValidationOptions,
  ValidationParameters,
} from "./types";

// Re-export constants from submodules
export {
  CHAIN_TOO_LONG,
  COMMAND_NOT_ATTENUATED,
  DIFFERENT_SUBJECTS,
  ISSUER_AUDIENCE_MISMATCH,
  MISSING_PROOF,
  NOT_BEFORE_BACKWARDS,
  PROOFS_MUST_BE_DELEGATIONS,
  ROOT_KEY_SIGNATURE_MISSING,
  SUBJECT_NOT_IN_CHAIN,
  TOO_MANY_PROOFS,
  UNCHAINED_PROOFS,
} from "./chain";
export { POLICY_TOO_DEEP, POLICY_TOO_WIDE } from "./policy";
export { INVALID_SIGNATURES } from "./signatures";
export { NOT_BEFORE_NOT_MET, TOKEN_EXPIRED } from "./temporal";
// Re-export types
export type {
  TokenRequirement,
  ValidationOptions,
  ValidationParameters,
} from "./types";

export const INVALID_AUDIENCE = "invalid audience";
export const NEED_DELEGATION = "token must be a delegation";
export const NEED_INVOCATION = "token must be an invocation";
export const POLICY_NOT_MET = "policy not met";

const DEFAULT_VALIDATION_PARAMETERS: Required<
  Omit<ValidationParameters, "tokenRequirements">
> = {
  maxChainLength: 5,
  maxPolicyWidth: 10,
  maxPolicyDepth: 5,
};

/**
 * Validates a NUC token envelope against a set of requirements and policies.
 * Performs comprehensive validation including signature verification, chain validation,
 * temporal checks, and policy evaluation.
 *
 * @param envelope - The token envelope to validate
 * @param options - Validation configuration
 * @param options.rootIssuers - Array of DIDs that are trusted root issuers
 * @param options.params - Optional validation parameters
 * @param options.params.maxChainLength - Maximum allowed chain length (default: 5)
 * @param options.params.maxPolicyWidth - Maximum policy width (default: 10)
 * @param options.params.maxPolicyDepth - Maximum policy depth (default: 5)
 * @param options.params.tokenRequirements - Optional token type and audience requirements
 * @param options.context - Optional context object for policy evaluation
 * @param options.timeProvider - Optional function returning current time in milliseconds (default: Date.now)
 *
 * @throws Validation errors are grouped by their origin:
 *
 * **Chain validation errors (from `./chain`):**
 * - `CHAIN_TOO_LONG` - If the token chain exceeds maxChainLength
 * - `TOO_MANY_PROOFS` - If a token references multiple proofs
 * - `PROOFS_MUST_BE_DELEGATIONS` - If a proof token is not a delegation
 * - `COMMAND_NOT_ATTENUATED` - If command is not properly attenuated in chain
 * - `DIFFERENT_SUBJECTS` - If subjects differ across the chain
 * - `ISSUER_AUDIENCE_MISMATCH` - If issuer/audience don't match in chain
 * - `MISSING_PROOF` - If a required proof is missing
 * - `NOT_BEFORE_BACKWARDS` - If notBefore times go backwards in chain
 * - `ROOT_KEY_SIGNATURE_MISSING` - If root signature is missing
 * - `SUBJECT_NOT_IN_CHAIN` - If subject is not found in chain
 * - `UNCHAINED_PROOFS` - If proofs are not properly chained
 *
 * **Signature validation errors (from `./signatures`):**
 * - `INVALID_SIGNATURES` - If any signature in the chain is invalid
 *
 * **Policy validation errors (from `./policy`):**
 * - `POLICY_NOT_MET` - If policy evaluation fails
 * - `POLICY_TOO_DEEP` - If policy depth exceeds maxPolicyDepth
 * - `POLICY_TOO_WIDE` - If policy width exceeds maxPolicyWidth
 *
 * **Temporal validation errors (from `./temporal`):**
 * - `TOKEN_EXPIRED` - If the token has expired
 * - `NOT_BEFORE_NOT_MET` - If the token is not yet valid
 *
 * **Token requirement errors (from this module):**
 * - `INVALID_AUDIENCE` - If the audience doesn't match requirements
 * - `NEED_DELEGATION` - If an invocation token is provided when delegation is required
 * - `NEED_INVOCATION` - If a delegation token is provided when invocation is required
 *
 * @example
 * ```typescript
 * import { validate } from "#/nuc/validate";
 * import { decodeBase64Url } from "#/nuc/codec";
 *
 * const envelope = decodeBase64Url(tokenString);
 *
 * validate(envelope, {
 *   rootIssuers: ["did:key:zDnae..."],
 *   params: {
 *     maxChainLength: 10,
 *     tokenRequirements: {
 *       type: "invocation",
 *       audience: "did:key:zDnae..."
 *     }
 *   },
 *   context: { resource: "users", action: "read" }
 * });
 * ```
 */
export function validate(envelope: Envelope, options: ValidationOptions): void {
  const {
    rootIssuers,
    params = {},
    context = {},
    timeProvider = () => Date.now(),
  } = options;
  const config = { ...DEFAULT_VALIDATION_PARAMETERS, ...params };

  if (envelope.proofs.length + 1 > config.maxChainLength) {
    Log.debug(
      {
        chainLength: envelope.proofs.length + 1,
        maxChainLength: config.maxChainLength,
      },
      CHAIN_TOO_LONG,
    );
    throw new Error(CHAIN_TOO_LONG);
  }

  const payload = envelope.nuc.payload;
  const proofBytes = getProofBytes(payload);

  if (proofBytes.length > 1) {
    Log.debug({ proofCount: proofBytes.length }, TOO_MANY_PROOFS);
    throw new Error(TOO_MANY_PROOFS);
  }

  const proofs = proofBytes.flatMap((proofHash) =>
    sortProofs(proofHash, envelope.proofs),
  );

  const now = timeProvider();

  validateProofs(payload, proofs, rootIssuers);
  const payloadChain = [...proofs.reverse(), payload];
  validatePayloadChain(payloadChain, config, now);
  validatePayload(payload, proofs, context, config.tokenRequirements);

  try {
    validateEnvelopeSignatures(envelope);
  } catch (error) {
    Log.debug({ error }, INVALID_SIGNATURES);
    throw new Error(INVALID_SIGNATURES);
  }
}

/**
 * Validates a token payload based on its type (delegation or invocation).
 * @internal
 */
function validatePayload(
  payload: Payload,
  proofs: Payload[],
  context: Record<string, unknown>,
  tokenRequirements?: TokenRequirement,
): void {
  if (isDelegationPayload(payload)) {
    validateDelegationPayload(payload, tokenRequirements);
  } else if (isInvocationPayload(payload)) {
    validateInvocationPayload(payload, proofs, context, tokenRequirements);
  }
}

/**
 * Validates a delegation token against token requirements.
 * @internal
 */
function validateDelegationPayload(
  payload: Payload,
  tokenRequirements?: TokenRequirement,
): void {
  if (!tokenRequirements) {
    return;
  }

  if (tokenRequirements.type === "invocation") {
    Log.debug(
      { expectedType: "invocation", actualType: "delegation" },
      NEED_INVOCATION,
    );
    throw new Error(NEED_INVOCATION);
  }

  if (tokenRequirements.type === "delegation") {
    if (!did.areEqual(payload.aud, did.parse(tokenRequirements.audience))) {
      Log.debug(
        { expected: tokenRequirements.audience, actual: payload.aud },
        INVALID_AUDIENCE,
      );
      throw new Error(INVALID_AUDIENCE);
    }
  }
}

/**
 * Validates an invocation token against policies and token requirements.
 * @internal
 */
function validateInvocationPayload(
  payload: Payload,
  proofs: Payload[],
  context: Record<string, unknown>,
  tokenRequirements?: TokenRequirement,
): void {
  const payloadJson = JSON.parse(JSON.stringify(payload));

  for (const proof of proofs) {
    validatePolicyEvaluates(proof, payloadJson, context);
  }

  if (!tokenRequirements) {
    return;
  }

  if (tokenRequirements.type === "delegation") {
    Log.debug(
      { expectedType: "delegation", actualType: "invocation" },
      NEED_DELEGATION,
    );
    throw new Error(NEED_DELEGATION);
  }

  if (tokenRequirements.type === "invocation") {
    if (!did.areEqual(payload.aud, did.parse(tokenRequirements.audience))) {
      Log.debug(
        { expected: tokenRequirements.audience, actual: payload.aud },
        INVALID_AUDIENCE,
      );
      throw new Error(INVALID_AUDIENCE);
    }
  }
}

/**
 * Validates that a proof's policies evaluate to true for the given payload.
 * @internal
 */
function validatePolicyEvaluates(
  proof: Payload,
  payloadJson: Record<string, unknown>,
  context: Record<string, unknown>,
): void {
  if (isInvocationPayload(proof)) {
    Log.debug({ proof }, PROOFS_MUST_BE_DELEGATIONS);
    throw new Error(PROOFS_MUST_BE_DELEGATIONS);
  }

  if (
    isDelegationPayload(proof) &&
    !evaluatePolicy(proof.pol, payloadJson, context)
  ) {
    Log.debug(
      { policy: proof.pol, payload: payloadJson, context },
      POLICY_NOT_MET,
    );
    throw new Error(POLICY_NOT_MET);
  }
}
