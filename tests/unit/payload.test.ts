import { describe, expect, it } from "vitest";
import { Did } from "#/core/did/did";
import { Keypair } from "#/core/keypair";
import { CommandSchema, Payload } from "#/nuc/payload";

const keypair = Keypair.generate();
const validDid = Did.serialize(keypair.toDid());

describe("Token Module", () => {
  describe("CommandSchema", () => {
    it("should parse a valid command", () => {
      const cmd = "/nuc/revoke";
      expect(CommandSchema.safeParse(cmd).success).toBe(true);
    });

    it("should fail if command does not start with '/'", () => {
      const cmd = "nuc/revoke";
      expect(CommandSchema.safeParse(cmd).success).toBe(false);
    });
  });

  describe("Payload.Schema", () => {
    const basePayload = {
      iss: validDid,
      aud: validDid,
      sub: validDid,
      cmd: "/test",
      nonce: "1234567890abcdef",
    };

    it("should parse a valid delegation payload", () => {
      const payload = { ...basePayload, pol: [["==", ".foo", "bar"]] };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(true);
    });

    it("should parse a valid invocation payload", () => {
      const payload = { ...basePayload, args: { foo: "bar" } };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(true);
    });

    it("should fail if both 'pol' and 'args' are present", () => {
      const payload = {
        ...basePayload,
        pol: [["==", ".foo", "bar"]],
        args: {},
      };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(false);
    });

    it("should fail if neither 'pol' nor 'args' are present", () => {
      const payload = { ...basePayload };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(false);
    });
  });
});
