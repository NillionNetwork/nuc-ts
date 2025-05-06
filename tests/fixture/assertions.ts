import * as fs from "node:fs";
import * as path from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";
import type { Record } from "effect";
import { Temporal } from "temporal-polyfill";
import { z } from "zod";
import { type NucTokenEnvelope, NucTokenEnvelopeSchema } from "#/envelope";
import { Did, DidSchema } from "#/token";
import {
  DelegationRequirement,
  InvocationRequirement,
  NucTokenValidator,
  ValidationParameters,
} from "#/validate";

export const ROOT_KEYS = [secp256k1.utils.randomPrivateKey()];
export const ROOT_DIDS = ROOT_KEYS.map(didFromPrivateKey);

export function didFromPrivateKey(key: Uint8Array): Did {
  return new Did(secp256k1.getPublicKey(key));
}

const TokenRequirementsSchema = z.union([
  z
    .object({
      invocation: DidSchema,
    })
    .transform(({ invocation }) => new InvocationRequirement(invocation)),
  z
    .object({
      delegation: DidSchema,
    })
    .transform(({ delegation }) => new DelegationRequirement(delegation)),
  z.literal("none").transform(() => undefined),
]);

const ValidationParametersSchema = z
  .object({
    max_chain_length: z.number(),
    max_policy_width: z.number(),
    max_policy_depth: z.number(),
    token_requirements: TokenRequirementsSchema,
  })
  .transform(
    (parameters) =>
      new ValidationParameters({
        maxChainLength: parameters.max_chain_length,
        maxPolicyWidth: parameters.max_policy_width,
        maxPolicyDepth: parameters.max_policy_depth,
        tokenRequirements: parameters.token_requirements,
      }),
  );

const AssertionInputSchema = z
  .object({
    token: NucTokenEnvelopeSchema,
    root_keys: z.array(z.string()),
    current_time: z.number(),
    context: z.record(z.string(), z.unknown()),
    parameters: ValidationParametersSchema,
  })
  .transform((input) => ({
    token: input.token,
    rootKeys: input.root_keys.map((key) => Did.fromHex(key)),
    currentTime: Temporal.Instant.fromEpochSeconds(input.current_time),
    context: input.context,
    parameters: input.parameters,
  }));
export type AssertInput = z.infer<typeof AssertionInputSchema>;

const AssertionExpectationSchema = z.discriminatedUnion("result", [
  z.object({
    result: z.literal("success"),
  }),
  z.object({
    result: z.literal("failure"),
    kind: z.string(),
  }),
]);
export type AssertionExpectation = z.infer<typeof AssertionExpectationSchema>;

const AssertionSchema = z.object({
  input: AssertionInputSchema,
  expectation: AssertionExpectationSchema,
});
export type Assertion = z.infer<typeof AssertionSchema>;

export type AsserterConfiguration = {
  parameters: ValidationParameters;
  rootDids: Did[];
  context: Record<string, unknown>;
  currentTime?: Temporal.Instant;
};

export class Asserter {
  private readonly config: AsserterConfiguration;
  constructor(config: Partial<AsserterConfiguration> = {}) {
    this.config = {
      parameters: new ValidationParameters(),
      rootDids: ROOT_DIDS,
      context: {},
      ...config,
    };
  }

  assertFailure(envelope: NucTokenEnvelope, message: string) {
    Asserter.log_tokens(envelope);
    const validator = this.validator(this.config.currentTime);
    try {
      validator.validate(envelope, this.config.parameters, this.config.context);
    } catch (e) {
      if (e instanceof Error) {
        if (e.message === message) {
          return;
        }
        throw new Error(`unexpected failed: ${e.message}`);
      }
    }
    throw new Error("did not fail");
  }

  assertSuccess(envelope: NucTokenEnvelope) {
    Asserter.log_tokens(envelope);
    this.validator(this.config.currentTime).validate(
      envelope,
      this.config.parameters,
      this.config.context,
    );
  }

  validator(currentTime?: Temporal.Instant): NucTokenValidator {
    if (currentTime) {
      return new NucTokenValidator(this.config.rootDids, () => currentTime);
    }
    return new NucTokenValidator(this.config.rootDids);
  }

  static log_tokens(envelope: NucTokenEnvelope) {
    console.log(`token being asserted: ${envelope.token.token.toString()}`);
    console.log(
      `proofs for it: ${envelope.proofs.map((proof) => proof.token.toString())}`,
    );
  }
}

export const TEST_ASSERTIONS = fs
  .readFileSync(path.resolve(__dirname, "../data/assertions.txt"), "utf-8")
  .split("\n")
  .filter((line) => line.trim() !== "")
  .map((line) => {
    return AssertionSchema.parse(JSON.parse(line));
  });
