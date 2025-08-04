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

export namespace Payload {
  export const DelegationSchema = CommonPayloadSchema.extend({
    pol: Policy.Schema,
  }).strict();

  export const InvocationSchema = CommonPayloadSchema.extend({
    args: z.record(z.string(), z.unknown()),
  }).strict();

  export const Schema = z.union([DelegationSchema, InvocationSchema]);

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

  export function getProofBytes(payload: Payload): Uint8Array[] {
    return payload.prf.map((prf) => hexToBytes(prf));
  }

  export function isInvocationPayload(
    payload: Payload,
  ): payload is InvocationPayload {
    return (payload as InvocationPayload).args !== undefined;
  }

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
