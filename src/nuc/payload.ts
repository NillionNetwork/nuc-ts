import { hexToBytes } from "@noble/hashes/utils";
import _ from "es-toolkit/compat";
import { z } from "zod";
import { Did } from "#/core/did/did";
import { Policy } from "#/nuc/policy";

export const CommandSchema = z.string().startsWith("/");
export type Command = z.infer<typeof CommandSchema>;

export const REVOKE_COMMAND: Command = "/nuc/revoke";

interface CommonPayload {
  iss: Did;
  aud: Did;
  sub: Did;
  nbf?: number;
  exp?: number;
  cmd: Command;
  meta?: Record<string, unknown>;
  nonce: string;
  prf: string[];
}

export interface DelegationPayload extends CommonPayload {
  pol: Policy;
}

export interface InvocationPayload extends CommonPayload {
  args: Record<string, unknown>;
}

export type Payload = DelegationPayload | InvocationPayload;

const CommonPayloadSchema = z.object({
  iss: Did.Schema,
  aud: Did.Schema,
  sub: Did.Schema,
  cmd: CommandSchema,
  nonce: z.string(),
  meta: z.record(z.string(), z.unknown()).optional(),
  prf: z.array(z.string()).default([]),
  nbf: z.number().optional(),
  exp: z.number().optional(),
});

/**
 * Provides utilities and schemas for working with NUC token payloads.
 *
 * The Payload namespace handles both delegation and invocation payloads,
 * providing type guards, validation schemas, and utility functions.
 *
 * @example
 * ```typescript
 * import { Payload } from "@nillion/nuc";
 *
 * // Check payload type
 * if (Payload.isDelegationPayload(payload)) {
 *   console.log("Policies:", payload.pol);
 * } else if (Payload.isInvocationPayload(payload)) {
 *   console.log("Arguments:", payload.args);
 * }
 *
 * // Validate with Zod
 * const validated = Payload.Schema.parse(unknownPayload);
 * ```
 */
export namespace Payload {
  /**
   * Zod schema for validating delegation payloads.
   *
   * Ensures the payload contains all required delegation fields
   * including the policy array.
   *
   * @example
   * ```typescript
   * const delegation = Payload.DelegationSchema.parse({
   *   iss: issuerDid,
   *   aud: audienceDid,
   *   sub: subjectDid,
   *   cmd: "/nil/db/data",
   *   pol: [["==", ".command", "/nil/db/data"]],
   *   nonce: "abc123",
   *   prf: []
   * });
   * ```
   */
  export const DelegationSchema = CommonPayloadSchema.extend({
    pol: Policy.Schema,
  }).strict();

  /**
   * Zod schema for validating invocation payloads.
   *
   * Ensures the payload contains all required invocation fields
   * including the arguments object.
   *
   * @example
   * ```typescript
   * const invocation = Payload.InvocationSchema.parse({
   *   iss: issuerDid,
   *   aud: serviceDid,
   *   sub: subjectDid,
   *   cmd: "/nil/db/query",
   *   args: { table: "users", limit: 100 },
   *   nonce: "xyz789",
   *   prf: [proofHash]
   * });
   * ```
   */
  export const InvocationSchema = CommonPayloadSchema.extend({
    args: z.record(z.string(), z.unknown()),
  }).strict();

  /**
   * Unified Zod schema for validating any NUC payload.
   *
   * Automatically determines whether the payload is a delegation
   * or invocation based on the presence of "pol" or "args" fields.
   *
   * @example
   * ```typescript
   * import { Payload } from "@nillion/nuc";
   *
   * const payload = Payload.Schema.parse(unknownPayload);
   *
   * // Type is automatically narrowed
   * if ('pol' in payload) {
   *   // TypeScript knows this is DelegationPayload
   *   console.log(payload.pol);
   * } else {
   *   // TypeScript knows this is InvocationPayload
   *   console.log(payload.args);
   * }
   * ```
   */
  export const Schema = z.union([DelegationSchema, InvocationSchema]);

  /**
   * Checks if a command is an attenuation of a parent command.
   *
   * Commands follow a hierarchical path structure. A command is an
   * attenuation if it extends the parent's path with additional segments.
   *
   * @param command - The command to check
   * @param parent - The parent command to compare against
   * @returns True if command is an attenuation of parent
   * @example
   * ```typescript
   * Payload.isCommandAttenuationOf("/nil/db/data", "/nil/db/data/read"); // true
   * Payload.isCommandAttenuationOf("/nil/db/data", "/nil/db/write"); // false
   * ```
   */
  export function isCommandAttenuationOf(
    command: Command,
    parent: Command,
  ): boolean {
    const commandSegments = command.slice(1).split("/").filter(Boolean);
    const parentSegments = parent.slice(1).split("/").filter(Boolean);

    return (
      commandSegments.length >= parentSegments.length &&
      _.isEqual(parentSegments, commandSegments.slice(0, parentSegments.length))
    );
  }

  /**
   * Extracts proof hashes from a payload as byte arrays.
   *
   * Converts the hex-encoded proof strings to Uint8Array format
   * for cryptographic operations.
   *
   * @param payload - The payload containing proof references
   * @returns Array of proof hashes as byte arrays
   * @example
   * ```typescript
   * const proofBytes = Payload.getProofBytes(payload);
   * console.log(proofBytes.length); // Number of proofs
   * ```
   */
  export function getProofBytes(payload: Payload): Uint8Array[] {
    return payload.prf.map((prf) => hexToBytes(prf));
  }

  /**
   * Type guard that checks if a payload is an invocation.
   *
   * @param payload - The payload to check
   * @returns True if the payload is an InvocationPayload
   * @example
   * ```typescript
   * if (Payload.isInvocationPayload(payload)) {
   *   // TypeScript knows payload.args exists
   *   console.log("Arguments:", payload.args);
   * }
   * ```
   */
  export function isInvocationPayload(
    payload: Payload,
  ): payload is InvocationPayload {
    return (payload as InvocationPayload).args !== undefined;
  }

  /**
   * Type guard that checks if a value is a delegation payload.
   *
   * Works with unknown values, making it safe for runtime validation.
   *
   * @param value - The value to check
   * @returns True if the value is a DelegationPayload
   * @example
   * ```typescript
   * if (Payload.isDelegationPayload(value)) {
   *   // TypeScript knows value.pol exists
   *   console.log("Policies:", value.pol);
   * }
   * ```
   */
  export function isDelegationPayload(
    value: unknown,
  ): value is DelegationPayload {
    return (
      value !== null &&
      value !== undefined &&
      typeof value === "object" &&
      "pol" in value
    );
  }
}
