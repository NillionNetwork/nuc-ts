import { Did } from "#/core/did/did";
import { Log } from "#/core/logger";
import type { Nuc } from "#/nuc/envelope";
import { Envelope } from "#/nuc/envelope";
import { Payload, REVOKE_COMMAND } from "#/nuc/payload";
import { bytesToHex } from "@noble/hashes/utils.js";

import { validatePolicyProperties } from "./policy";
import { validateTemporalProperties } from "./temporal";
import type { ValidationParameters } from "./types";

export const CHAIN_TOO_LONG = "token chain is too long";
export const COMMAND_NOT_ATTENUATED = "command is not an attenuation";
export const DIFFERENT_SUBJECTS = "different subjects in chain";
export const ISSUER_AUDIENCE_MISMATCH = "issuer/audience mismatch";
export const MISSING_PROOF = "proof is missing";
export const NOT_BEFORE_BACKWARDS = "`not before` cannot move backwards";
export const PROOFS_MUST_BE_DELEGATIONS = "proofs must be delegations";
export const ROOT_KEY_SIGNATURE_MISSING = "root NUC is not signed by a root issuer";
export const SUBJECT_NOT_IN_CHAIN = "subject not in chain";
export const TOO_MANY_PROOFS = "up to one `prf` in a token is allowed";
export const UNCHAINED_PROOFS = "extra proofs not part of chain provided";

/**
 * Validate proof chain
 */
export function validateProofs(payload: Payload, proofs: Payload[], rootIssuers: string[]): void {
  if (rootIssuers.length > 0) {
    const root = proofs.length > 0 ? proofs[proofs.length - 1] : payload;
    if (!rootIssuers.some((issuer) => Did.areEqual(Did.parse(issuer), root.iss))) {
      Log.debug({ rootIssuer: root.iss, expectedIssuers: rootIssuers }, ROOT_KEY_SIGNATURE_MISSING);
      throw new Error(ROOT_KEY_SIGNATURE_MISSING);
    }
  }

  for (const proof of proofs) {
    if (Payload.isInvocationPayload(proof)) {
      Log.debug({ proof }, PROOFS_MUST_BE_DELEGATIONS);
      throw new Error(PROOFS_MUST_BE_DELEGATIONS);
    }
  }
}

export function getConsecutivePairs<T>(input: Array<T>): Array<Array<T>> {
  return input.slice(0, -1).map((item, index) => [item, input[index + 1]]);
}

/**
 * Validate token chain properties
 */
export function validatePayloadChain(
  payloads: Payload[],
  config: Required<Omit<ValidationParameters, "tokenRequirements">>,
  now: number,
): void {
  for (const [previous, current] of getConsecutivePairs(payloads)) {
    validateRelationshipProperties(previous, current);
  }

  for (const payload of payloads) {
    validateTemporalProperties(payload, now);
    if (Payload.isDelegationPayload(payload)) {
      validatePolicyProperties(payload.pol, config);
    }
  }

  if (payloads.length >= 2) {
    const payload = payloads[1];
    if (!Did.areEqual(payload.iss, payload.sub)) {
      Log.debug({ issuer: payload.iss, subject: payload.sub }, SUBJECT_NOT_IN_CHAIN);
      throw new Error(SUBJECT_NOT_IN_CHAIN);
    }
  }
}

/**
 * Validate relationship between consecutive tokens
 */
export function validateRelationshipProperties(previous: Payload, current: Payload): void {
  if (!Did.areEqual(previous.aud, current.iss)) {
    Log.debug({ expected: previous.aud, actual: current.iss }, ISSUER_AUDIENCE_MISMATCH);
    throw new Error(ISSUER_AUDIENCE_MISMATCH);
  }

  if (!Did.areEqual(previous.sub, current.sub)) {
    Log.debug({ previousSubject: previous.sub, currentSubject: current.sub }, DIFFERENT_SUBJECTS);
    throw new Error(DIFFERENT_SUBJECTS);
  }

  if (!Payload.isCommandAttenuationOf(current.cmd, previous.cmd) && current.cmd !== REVOKE_COMMAND) {
    Log.debug({ previousCommand: previous.cmd, currentCommand: current.cmd }, COMMAND_NOT_ATTENUATED);
    throw new Error(COMMAND_NOT_ATTENUATED);
  }

  if (previous.nbf && current.nbf && previous.nbf > current.nbf) {
    Log.debug({ previousNbf: previous.nbf, currentNbf: current.nbf }, NOT_BEFORE_BACKWARDS);
    throw new Error(NOT_BEFORE_BACKWARDS);
  }
}

/**
 * Reconstructs the cryptographic chain of trust from an unordered bag of proofs.
 *
 * This function addresses a key challenge in the Nuc specification: proof tokens
 * are provided as an unordered array, but validation requires them to be processed
 * in their correct chain order (from leaf to root). The algorithm works by:
 *
 * 1. Starting with the provided hash (typically from the leaf token's `prf` field)
 * 2. Finding the proof token whose hash matches this value
 * 3. Following that proof's `prf` field to find the next proof in the chain
 * 4. Repeating until we reach a root token (one with no `prf` field)
 *
 * This process effectively traverses the chain backwards from leaf to root,
 * building an ordered list of proofs that can be validated sequentially.
 *
 * @param hash - The hash to start searching from (usually from a token's prf field)
 * @param proofs - Unordered array of proof tokens
 * @returns Ordered array of proof payloads from leaf to root
 * @throws {Error} TOO_MANY_PROOFS - If any proof references multiple parent proofs
 * @throws {Error} UNCHAINED_PROOFS - If proofs remain after chain reconstruction (indicates broken chain)
 */
export function sortProofs(hash: Uint8Array, proofs: Nuc[]): Payload[] {
  const indexedProofs: Array<[string, Payload]> = proofs.map((proof) => [
    bytesToHex(Envelope.computeHash(proof)),
    proof.payload,
  ]);

  const sortedProofs: Payload[] = [];
  let nextHash: string | null = bytesToHex(hash);

  while (nextHash) {
    const nextProofIndex = indexedProofs.findIndex(([hash, _]) => hash === nextHash);

    if (nextProofIndex < 0) {
      Log.debug({ missingHash: nextHash }, MISSING_PROOF);
      throw new Error(MISSING_PROOF);
    }

    const nextProof = indexedProofs.splice(nextProofIndex, 1)[0][1];
    sortedProofs.push(nextProof);

    const nextProofBytes = Payload.getProofBytes(nextProof);
    if (nextProofBytes.length > 1) {
      Log.debug({ proofCount: nextProofBytes.length }, TOO_MANY_PROOFS);
      throw new Error(TOO_MANY_PROOFS);
    }

    nextHash = nextProofBytes[0] ? bytesToHex(nextProofBytes[0]) : null;
  }

  if (indexedProofs.length > 0) {
    Log.debug({ unchainedProofCount: indexedProofs.length }, UNCHAINED_PROOFS);
    throw new Error(UNCHAINED_PROOFS);
  }

  return sortedProofs;
}
