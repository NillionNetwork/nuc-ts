import { Did } from "#/core/did/did";
import { Signer } from "#/core/signer";
import { CommandSchema, Payload } from "#/nuc/payload";
import { describe, expect, it } from "vitest";

describe("Token Module", () => {
  // Generate signer for reuse
  const signer = Signer.generate();
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
    it("should parse a valid delegation payload", async () => {
      const validDid = Did.serialize(await signer.getDid());
      const basePayload = {
        iss: validDid,
        aud: validDid,
        sub: validDid,
        cmd: "/test",
        nonce: "1234567890abcdef",
      };
      const payload = { ...basePayload, pol: [["==", ".foo", "bar"]] };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(true);
    });

    it("should parse a valid invocation payload", async () => {
      const validDid = Did.serialize(await signer.getDid());
      const basePayload = {
        iss: validDid,
        aud: validDid,
        sub: validDid,
        cmd: "/test",
        nonce: "1234567890abcdef",
      };
      const payload = { ...basePayload, args: { foo: "bar" } };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(true);
    });

    it("should fail if both 'pol' and 'args' are present", async () => {
      const validDid = Did.serialize(await signer.getDid());
      const basePayload = {
        iss: validDid,
        aud: validDid,
        sub: validDid,
        cmd: "/test",
        nonce: "1234567890abcdef",
      };
      const payload = {
        ...basePayload,
        pol: [["==", ".foo", "bar"]],
        args: {},
      };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(false);
    });

    it("should fail if neither 'pol' nor 'args' are present", async () => {
      const validDid = Did.serialize(await signer.getDid());
      const basePayload = {
        iss: validDid,
        aud: validDid,
        sub: validDid,
        cmd: "/test",
        nonce: "1234567890abcdef",
      };
      const payload = { ...basePayload };
      const result = Payload.Schema.safeParse(payload);
      expect(result.success).toBe(false);
    });
  });
});
