import * as fs from "node:fs";
import * as path from "node:path";
import { Temporal } from "temporal-polyfill";
import { z } from "zod";
import { NucTokenEnvelopeSchema } from "#/envelope";
import { Did, DidSchema } from "#/token";
import {
  DelegationRequirement,
  InvocationRequirement,
  ValidationParameters,
} from "#/validate";

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

const AssertionSchema = z
  .object({
    input: AssertionInputSchema,
    expectation: AssertionExpectationSchema,
  })
  .transform(({ input, expectation }) => new Assertion(input, expectation));

export class Assertion {
  constructor(
    public readonly input: AssertInput,
    public readonly expectation: AssertionExpectation,
  ) {}
}

const filePath = path.resolve(__dirname, "../data/assertions.txt");
export const assertions = fs
  .readFileSync(filePath, "utf-8")
  .split("\n")
  .filter((line) => line.trim() !== "")
  .map((line) => {
    return AssertionSchema.parse(JSON.parse(line));
  });
