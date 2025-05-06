import { Temporal } from "temporal-polyfill";
import type { DecodedNucToken, NucTokenEnvelope } from "#/envelope";
import { And, AnyOf, Equals, Not, NotEquals, Or, type Policy } from "#/policy";
import {
  DelegationBody,
  type Did,
  InvocationBody,
  type NucToken,
  REVOKE_COMMAND,
} from "#/token";
import { pairwise } from "#/utils";

export const CHAIN_TOO_LONG = "token chain is too long";
export const COMMAND_NOT_ATTENUATED = "command is not an attenuation";
export const DIFFERENT_SUBJECTS = "different subjects in chain";
export const INVALID_AUDIENCE = "invalid audience";
export const INVALID_SIGNATURES = "invalid signatures";
export const ISSUER_AUDIENCE_MISMATCH = "issuer/audience mismatch";
export const MISSING_PROOF = "proof is missing";
export const NEED_DELEGATION = "token must be a delegation";
export const NEED_INVOCATION = "token must be an invocation";
export const NOT_BEFORE_BACKWARDS = "`not before` cannot move backwards";
export const NOT_BEFORE_NOT_MET = "`not before` date not met";
export const POLICY_NOT_MET = "policy not met";
export const POLICY_TOO_DEEP = "policy is too deep";
export const POLICY_TOO_WIDE = "policy is too wide";
export const PROOFS_MUST_BE_DELEGATIONS = "proofs must be delegations";
export const ROOT_KEY_SIGNATURE_MISSING =
  "root NUC is not signed by root keypair";
export const SUBJECT_NOT_IN_CHAIN = "subject not in chain";
export const TOKEN_EXPIRED = "token is expired";
export const TOO_MANY_PROOFS = "up to one `prf` in a token is allowed";
export const UNCHAINED_PROOFS = "extra proofs not part of chain provided";

export class InvocationRequirement {
  constructor(public audience: Did) {}
}

export class DelegationRequirement {
  constructor(public audience: Did) {}
}

export type ValidationParametersConfig = {
  maxChainLength: number;
  maxPolicyWidth: number;
  maxPolicyDepth: number;
  tokenRequirements?: InvocationRequirement | DelegationRequirement;
};

export class ValidationParameters {
  public readonly config: ValidationParametersConfig;
  constructor(config?: Partial<ValidationParametersConfig>) {
    this.config = {
      maxChainLength: 5,
      maxPolicyWidth: 10,
      maxPolicyDepth: 5,
      ...config,
    };
  }
}

export class NucTokenValidator {
  constructor(
    private readonly rootIssuers: Array<Did>,
    public timeProvider: () => Temporal.Instant = () => Temporal.Now.instant(),
  ) {}

  validate(
    envelope: NucTokenEnvelope,
    parameters: ValidationParameters,
    context: Record<string, unknown> = {},
  ): void {
    if (envelope.proofs.length + 1 > parameters.config.maxChainLength) {
      throw new Error(CHAIN_TOO_LONG);
    }

    const token = envelope.token.token;
    if (token.proofs.length > 1) {
      throw new Error(TOO_MANY_PROOFS);
    }
    const proofs = token.proofs.flatMap((proofHash) =>
      NucTokenValidator.sortProofs(proofHash, envelope.proofs),
    );

    const now = this.timeProvider();
    this.validateProofs(token, proofs);
    const tokenChain = [...proofs.reverse(), token];
    NucTokenValidator.validateTokenChain(tokenChain, parameters, now);
    NucTokenValidator.validateToken(
      token,
      proofs,
      context,
      parameters.config.tokenRequirements,
    );
    try {
      envelope.validateSignatures();
    } catch (_) {
      throw new Error(INVALID_SIGNATURES);
    }
  }

  validateProofs(token: NucToken, proofs: Array<NucToken>): void {
    if (this.rootIssuers.length > 0) {
      const root = proofs.length > 0 ? proofs[proofs.length - 1] : token;
      if (!this.rootIssuers.some((issuer) => issuer.isEqual(root.issuer))) {
        throw new Error(ROOT_KEY_SIGNATURE_MISSING);
      }
    }
    for (const proof of proofs) {
      if (proof.body instanceof InvocationBody) {
        throw new Error(PROOFS_MUST_BE_DELEGATIONS);
      }
    }
  }

  static validateTokenChain(
    tokens: Array<NucToken>,
    parameters: ValidationParameters,
    now: Temporal.Instant,
  ): void {
    for (const [previous, current] of pairwise(tokens)) {
      NucTokenValidator.validateRelationshipProperties(previous, current);
    }
    for (const token of tokens) {
      NucTokenValidator.validateTemporalProperties(token, now);
      if (token.body instanceof DelegationBody) {
        NucTokenValidator.validatePoliciesProperties(
          token.body.policies,
          parameters,
        );
      }
    }
    if (tokens.length >= 2) {
      const token = tokens[1];
      if (!token.issuer.isEqual(token.subject)) {
        throw new Error(SUBJECT_NOT_IN_CHAIN);
      }
    }
  }

  static validateRelationshipProperties(
    previous: NucToken,
    current: NucToken,
  ): void {
    if (!previous.audience.isEqual(current.issuer)) {
      throw new Error(ISSUER_AUDIENCE_MISMATCH);
    }
    if (!previous.subject.isEqual(current.subject)) {
      throw new Error(DIFFERENT_SUBJECTS);
    }
    if (
      !current.command.isAttenuationOf(previous.command) &&
      !current.command.isAttenuationOf(REVOKE_COMMAND)
    ) {
      throw new Error(COMMAND_NOT_ATTENUATED);
    }
    if (
      previous.notBefore &&
      current.notBefore &&
      previous.notBefore.epochSeconds > current.notBefore.epochSeconds
    ) {
      throw new Error(NOT_BEFORE_BACKWARDS);
    }
  }

  static validateTemporalProperties(
    token: NucToken,
    currentTime: Temporal.Instant,
  ): void {
    if (
      token.expiresAt &&
      token.expiresAt.epochSeconds <= currentTime.epochSeconds
    ) {
      throw new Error(TOKEN_EXPIRED);
    }
    if (
      token.notBefore &&
      token.notBefore.epochSeconds > currentTime.epochSeconds
    ) {
      throw new Error(NOT_BEFORE_NOT_MET);
    }
  }

  static validatePoliciesProperties(
    policies: Array<Policy>,
    parameters: ValidationParameters,
  ): void {
    if (policies.length > parameters.config.maxPolicyWidth) {
      throw new Error(POLICY_TOO_WIDE);
    }
    for (const policy of policies) {
      const properties = PolicyTreeProperties.fromPolicy(policy);
      if (properties.maxWidth > parameters.config.maxPolicyWidth) {
        throw new Error(POLICY_TOO_WIDE);
      }
      if (properties.maxDepth > parameters.config.maxPolicyDepth) {
        throw new Error(POLICY_TOO_DEEP);
      }
    }
  }

  static validateToken(
    token: NucToken,
    proofs: Array<NucToken>,
    context: Record<string, unknown>,
    tokenRequirements?: InvocationRequirement | DelegationRequirement,
  ): void {
    switch (token.body.constructor) {
      case DelegationBody:
        NucTokenValidator.validateDelegationToken(token, tokenRequirements);
        break;
      case InvocationBody:
        NucTokenValidator.validateInvocationToken(
          token,
          proofs,
          context,
          tokenRequirements,
        );
        break;
    }
  }

  static validateDelegationToken(
    token: NucToken,
    tokenRequirements?: InvocationRequirement | DelegationRequirement,
  ): void {
    if (!tokenRequirements) {
      return;
    }
    switch (tokenRequirements.constructor) {
      case InvocationRequirement:
        throw new Error(NEED_INVOCATION);
      case DelegationRequirement:
        if (!token.audience.isEqual(tokenRequirements?.audience)) {
          throw new Error(INVALID_AUDIENCE);
        }
    }
  }

  static validateInvocationToken(
    token: NucToken,
    proofs: Array<NucToken>,
    context: Record<string, unknown>,
    tokenRequirements?: InvocationRequirement | DelegationRequirement,
  ): void {
    const tokenJson = token.toJson();
    for (const proof of proofs) {
      NucTokenValidator.validatePolicyEvaluates(proof, tokenJson, context);
    }
    if (!tokenRequirements) {
      return;
    }
    switch (tokenRequirements.constructor) {
      case DelegationRequirement:
        throw new Error(NEED_DELEGATION);
      case InvocationRequirement:
        if (!token.audience.isEqual(tokenRequirements?.audience)) {
          throw new Error(INVALID_AUDIENCE);
        }
    }
  }

  static validatePolicyEvaluates(
    proof: NucToken,
    tokenJson: Record<string, unknown>,
    context: Record<string, unknown>,
  ): void {
    switch (true) {
      case proof.body instanceof InvocationBody:
        throw new Error(PROOFS_MUST_BE_DELEGATIONS);
      case proof.body instanceof DelegationBody: {
        for (const policy of proof.body.policies) {
          if (!policy.evaluate(tokenJson, context)) {
            throw new Error(POLICY_NOT_MET);
          }
        }
      }
    }
  }

  static sortProofs(
    hash: Uint8Array,
    proofs: Array<DecodedNucToken>,
  ): Array<NucToken> {
    const indexedProofs: Array<[Uint8Array, NucToken]> = proofs.map((proof) => [
      proof.computeHash(),
      proof.token,
    ]);
    const sortedProofs: NucToken[] = [];
    let nextHash = hash;
    while (nextHash) {
      const nextProofIndex = indexedProofs.findIndex(
        ([hash, _]) => Buffer.from(hash).compare(Buffer.from(nextHash)) === 0,
      );
      if (nextProofIndex < 0) {
        throw new Error(MISSING_PROOF);
      }
      const nextProof = indexedProofs.splice(nextProofIndex, 1)[0][1];
      sortedProofs.push(nextProof);
      if (nextProof.proofs.length > 1) {
        throw new Error(TOO_MANY_PROOFS);
      }
      nextHash = nextProof.proofs[0];
    }
    if (indexedProofs && indexedProofs.length > 0) {
      throw new Error(UNCHAINED_PROOFS);
    }
    return sortedProofs;
  }
}

export class PolicyTreeProperties {
  constructor(private properties: { maxDepth: number; maxWidth: number }) {}

  get maxDepth(): number {
    return this.properties.maxDepth;
  }

  set maxDepth(value: number) {
    this.properties.maxDepth = value;
  }

  get maxWidth(): number {
    return this.properties.maxWidth;
  }

  set maxWidth(value: number) {
    this.properties.maxWidth = value;
  }

  static fromPolicy(rootPolicy: Policy): PolicyTreeProperties {
    switch (true) {
      case rootPolicy instanceof And:
      case rootPolicy instanceof Or: {
        const properties = new PolicyTreeProperties({
          maxDepth: 0,
          maxWidth: rootPolicy.conditions.length,
        });
        for (const policy of rootPolicy.conditions) {
          const innerProperties = PolicyTreeProperties.fromPolicy(policy);
          properties.maxDepth = Math.max(
            innerProperties.maxDepth,
            properties.maxDepth,
          );
          properties.maxWidth = Math.max(
            innerProperties.maxWidth,
            properties.maxWidth,
          );
        }
        properties.maxDepth += 1;
        return properties;
      }
      case rootPolicy instanceof Not: {
        const properties = PolicyTreeProperties.fromPolicy(
          rootPolicy.condition,
        );
        properties.maxDepth += 1;
        return properties;
      }
      case rootPolicy instanceof Equals:
      case rootPolicy instanceof NotEquals: {
        return new PolicyTreeProperties({ maxDepth: 1, maxWidth: 1 });
      }
      case rootPolicy instanceof AnyOf: {
        return new PolicyTreeProperties({
          maxDepth: 1,
          maxWidth: rootPolicy.options.length,
        });
      }
      default:
        throw new Error("policy is not supported");
    }
  }
}
