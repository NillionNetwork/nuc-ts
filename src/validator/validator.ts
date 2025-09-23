import { Did } from "#/core/did/did";
import { Log } from "#/core/logger";
import type { Envelope } from "#/nuc/envelope";
import { Payload } from "#/nuc/payload";
import { Policy } from "#/nuc/policy";
import {
  CHAIN_TOO_LONG,
  PROOFS_MUST_BE_DELEGATIONS,
  sortProofs,
  TOO_MANY_PROOFS,
  validatePayloadChain,
  validateProofs,
} from "./chain";
import { INVALID_SIGNATURES, validateEnvelopeSignature } from "./signatures";
import type {
  TokenRequirement,
  ValidationOptions,
  ValidationParameters,
} from "./types";

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

export namespace Validator {
  /**
   * Validates a NUC token envelope against requirements and policies.
   *
   * Performs comprehensive validation including signature verification,
   * chain validation, temporal checks, and policy evaluation.
   *
   * @param envelope - The token envelope to validate
   * @param options - Validation configuration
   * @param options.rootIssuers Array of trusted root issuer `Did` strings.
   * @param options.params - Optional validation parameters
   * @param options.params.maxChainLength - Maximum allowed chain length (default: 5)
   * @param options.params.maxPolicyWidth - Maximum policy width (default: 10)
   * @param options.params.maxPolicyDepth - Maximum policy depth (default: 5)
   * @param options.params.tokenRequirements - Optional token type and audience requirements
   * @param options.context - Optional context object for policy evaluation
   * @param options.timeProvider - Optional function returning current time in milliseconds (default: Date.now)
   * @returns void - Validation succeeds silently
   * @throws {Error} CHAIN_TOO_LONG - Token chain exceeds maxChainLength
   * @throws {Error} TOO_MANY_PROOFS - Token references multiple proofs
   * @throws {Error} PROOFS_MUST_BE_DELEGATIONS - Proof token is not a delegation
   * @throws {Error} COMMAND_NOT_ATTENUATED - Command is not properly attenuated in chain
   * @throws {Error} DIFFERENT_SUBJECTS - Subjects differ across the chain
   * @throws {Error} ISSUER_AUDIENCE_MISMATCH - Issuer/audience don't match in chain
   * @throws {Error} MISSING_PROOF - Required proof is missing
   * @throws {Error} NOT_BEFORE_BACKWARDS - notBefore times go backwards in chain
   * @throws {Error} ROOT_KEY_SIGNATURE_MISSING - Root signature is missing
   * @throws {Error} SUBJECT_NOT_IN_CHAIN - Subject is not found in chain
   * @throws {Error} UNCHAINED_PROOFS - Proofs are not properly chained
   * @throws {Error} INVALID_SIGNATURES - Any signature in the chain is invalid
   * @throws {Error} POLICY_NOT_MET - Policy evaluation fails
   * @throws {Error} POLICY_TOO_DEEP - Policy depth exceeds maxPolicyDepth
   * @throws {Error} POLICY_TOO_WIDE - Policy width exceeds maxPolicyWidth
   * @throws {Error} TOKEN_EXPIRED - Token has expired
   * @throws {Error} NOT_BEFORE_NOT_MET - Token is not yet valid
   * @throws {Error} INVALID_AUDIENCE - Audience doesn't match requirements
   * @throws {Error} NEED_DELEGATION - Invocation provided when delegation required
   * @throws {Error} NEED_INVOCATION - Delegation provided when invocation required
   * @example
   * ```typescript
   * import { Validator, Codec } from "@nillion/nuc";
   *
   * const envelope = Codec.decodeBase64Url(tokenString);
   *
   * try {
   *   Validator.validate(envelope, {
   *     rootIssuers: ["did:key:zDnae..."],
   *     params: {
   *       maxChainLength: 10,
   *       tokenRequirements: {
   *         type: "invocation",
   *         audience: "did:key:zDnae..."
   *       }
   *     },
   *     context: { resource: "users", action: "read" }
   *   });
   * } catch (error) {
   *   if (error.message === Validator.TOKEN_EXPIRED) {
   *     console.error("Token has expired");
   *   }
   * }
   * ```
   */
  export function validate(
    envelope: Envelope,
    options: ValidationOptions,
  ): void {
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
    const proofBytes = Payload.getProofBytes(payload);

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
      validateEnvelopeSignature(envelope);
    } catch (error) {
      Log.debug({ error }, INVALID_SIGNATURES);
      throw new Error(INVALID_SIGNATURES);
    }
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
  if (Payload.isDelegationPayload(payload)) {
    validateDelegationPayload(payload, tokenRequirements);
  } else if (Payload.isInvocationPayload(payload)) {
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
    if (!Did.areEqual(payload.aud, Did.parse(tokenRequirements.audience))) {
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
    if (!Did.areEqual(payload.aud, Did.parse(tokenRequirements.audience))) {
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
  if (Payload.isInvocationPayload(proof)) {
    Log.debug({ proof }, PROOFS_MUST_BE_DELEGATIONS);
    throw new Error(PROOFS_MUST_BE_DELEGATIONS);
  }

  if (
    Payload.isDelegationPayload(proof) &&
    !Policy.evaluatePolicy(proof.pol, payloadJson, context)
  ) {
    Log.debug(
      { policy: proof.pol, payload: payloadJson, context },
      POLICY_NOT_MET,
    );
    throw new Error(POLICY_NOT_MET);
  }
}
