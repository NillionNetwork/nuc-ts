import * as fs from "node:fs";
import * as path from "node:path";
import { hexToBytes } from "@noble/hashes/utils";
import { z } from "zod";
import * as didNil from "#/core/did/nil";
import { Codec } from "#/nuc/codec";
import type {
  TokenRequirement,
  ValidationParameters,
} from "#/validator/validator";

// Schema for parsing the `token_requirements` field from the text file.
const TokenReqSchema = z.union([
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

// Schema for parsing the `parameters` field from the text file.
const ValidationParamsSchema = z
  .object({
    max_chain_length: z.number(),
    max_policy_width: z.number(),
    max_policy_depth: z.number(),
    token_requirements: TokenReqSchema,
  })
  .transform(
    (p): ValidationParameters => ({
      maxChainLength: p.max_chain_length,
      maxPolicyWidth: p.max_policy_width,
      maxPolicyDepth: p.max_policy_depth,
      tokenRequirements: p.token_requirements,
    }),
  );

// Schema for parsing the entire `input` object from the text file.
const InputSchema = z
  .object({
    token: z.string().transform(Codec.decodeBase64Url),
    root_keys: z.array(z.string()),
    current_time: z.number(),
    context: z.record(z.string(), z.unknown()),
    parameters: ValidationParamsSchema,
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

// Schema for parsing the `expectation` object from the text file.
const ExpectationSchema = z.discriminatedUnion("result", [
  z.object({
    result: z.literal("success"),
  }),
  z.object({
    result: z.literal("failure"),
    kind: z.string(),
  }),
]);

// Schema for parsing a full line (one assertion) from the text file.
const AssertionSchema = z.object({
  input: InputSchema,
  expectation: ExpectationSchema,
});

// Read and parse the entire assertions.txt file.
export const NucRsCompatAssertions = fs
  .readFileSync(path.resolve(__dirname, "./nuc-rs-compat-data.txt"), "utf-8")
  .split("\n")
  .filter((line) => line.trim() !== "")
  .map((line) => {
    return AssertionSchema.parse(JSON.parse(line));
  });
