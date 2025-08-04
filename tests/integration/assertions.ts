import * as fs from "node:fs";
import * as path from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";
import { hexToBytes } from "@noble/hashes/utils";
import { z } from "zod";
import * as didNil from "#/core/did/nil";
import { Codec } from "#/nuc/codec";
import type { Envelope } from "#/nuc/envelope";
import {
  type TokenRequirement,
  type ValidationParameters,
  Validator,
} from "#/validator";

export const ROOT_KEYS = [secp256k1.utils.randomSecretKey()];
export const ROOT_DIDS: string[] = ROOT_KEYS.map((privKey) =>
  didNil.fromPublicKeyBytes(secp256k1.getPublicKey(privKey)),
);

const TokenRequirementsSchema = z.union([
  z.object({ invocation: z.string() }).transform(
    (val): TokenRequirement => ({
      type: "invocation",
      audience: val.invocation,
    }),
  ),
  z.object({ delegation: z.string() }).transform(
    (val): TokenRequirement => ({
      type: "delegation",
      audience: val.delegation,
    }),
  ),
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
    (p): ValidationParameters => ({
      maxChainLength: p.max_chain_length,
      maxPolicyWidth: p.max_policy_width,
      maxPolicyDepth: p.max_policy_depth,
      tokenRequirements: p.token_requirements,
    }),
  );

const AssertionInputSchema = z
  .object({
    token: z.string().transform(Codec.decodeBase64Url),
    root_keys: z.array(z.string()),
    current_time: z.number(),
    context: z.record(z.string(), z.unknown()),
    parameters: ValidationParametersSchema,
  })
  .transform((input) => ({
    token: input.token,
    rootKeys: input.root_keys.map((hexKey) =>
      didNil.fromPublicKeyBytes(hexToBytes(hexKey)),
    ),
    currentTime: input.current_time * 1000,
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
  parameters?: ValidationParameters;
  rootDids?: string[];
  context?: Record<string, unknown>;
  currentTime?: number;
};

export class Asserter {
  private readonly config: AsserterConfiguration;
  constructor(config: AsserterConfiguration = {}) {
    this.config = {
      rootDids: ROOT_DIDS,
      ...config,
    };
  }

  assertFailure(envelope: Envelope, message: string) {
    const timeProvider =
      this.config.currentTime !== undefined
        ? () => this.config.currentTime!
        : undefined;
    try {
      Validator.validate(envelope, {
        rootIssuers: this.config.rootDids!,
        params: this.config.parameters,
        context: this.config.context,
        timeProvider,
      });
    } catch (e) {
      if (e instanceof Error) {
        if (e.message === message) {
          return;
        }
        throw new Error(
          `Validation failed with unexpected message: expected '${message}', got '${e.message}'`,
        );
      }
    }
    throw new Error(
      `Validation succeeded but was expected to fail with: ${message}`,
    );
  }

  assertSuccess(envelope: Envelope) {
    const timeProvider =
      this.config.currentTime !== undefined
        ? () => this.config.currentTime!
        : undefined;
    Validator.validate(envelope, {
      rootIssuers: this.config.rootDids!,
      params: this.config.parameters,
      context: this.config.context,
      timeProvider,
    });
  }
}

export const TEST_ASSERTIONS = fs
  .readFileSync(path.resolve(__dirname, "./assertions.txt"), "utf-8")
  .split("\n")
  .filter((line) => line.trim() !== "")
  .map((line) => {
    return AssertionSchema.parse(JSON.parse(line));
  });
