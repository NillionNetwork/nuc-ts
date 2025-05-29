import { secp256k1 } from "@noble/curves/secp256k1";
import { Temporal } from "temporal-polyfill";
import { describe, it } from "vitest";
import { NucTokenBuilder } from "#/builder";
import { NucTokenEnvelopeSchema } from "#/envelope";
import { Equals } from "#/policy";
import { SelectorSchema } from "#/selector";
import { Command, DelegationBody, Did, NucToken } from "#/token";
import { base64UrlDecode } from "#/utils";

describe("nuc token builder", () => {
  it("extend", ({ expect }) => {
    const key = secp256k1.utils.randomPrivateKey();
    const base = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".foo"), 42),
    ])
      .audience(new Did(Uint8Array.from(Array(33).fill(0xbb))))
      .subject(new Did(Uint8Array.from(Array(33).fill(0xcc))))
      .command(new Command(["nil", "db", "read"]))
      .build(key);
    const baseToken = NucTokenEnvelopeSchema.parse(base);

    const ext = NucTokenBuilder.extending(baseToken)
      .audience(new Did(Uint8Array.from(Array(33).fill(0xdd))))
      .build(key);
    const extToken = NucTokenEnvelopeSchema.parse(ext);

    expect(extToken.token.token.command).toStrictEqual(
      baseToken.token.token.command,
    );
    expect(extToken.token.token.subject).toStrictEqual(
      baseToken.token.token.subject,
    );
    expect(extToken.proofs.length).toBe(1);
    expect(extToken.proofs[0]).toStrictEqual(baseToken.token);
  });

  it("encode decode", ({ expect }) => {
    const key = secp256k1.utils.randomPrivateKey();
    const token = NucTokenBuilder.delegation([])
      .audience(new Did(Uint8Array.from(Array(33).fill(0xbb))))
      .subject(new Did(Uint8Array.from(Array(33).fill(0xcc))))
      .command(new Command(["nil", "db", "read"]))
      .notBefore(1740494955)
      .expiresAt(1740495955)
      .nonce("010203")
      .meta({ name: "bob" })
      .build(key);
    const envelope = NucTokenEnvelopeSchema.parse(token);
    envelope.validateSignatures();

    const [header, _] = token.split(".");
    expect(JSON.parse(base64UrlDecode(header))).toStrictEqual({
      alg: "ES256K",
    });

    const expectedToken = new NucToken({
      issuer: new Did(secp256k1.getPublicKey(key)),
      audience: new Did(Uint8Array.from(Array(33).fill(0xbb))),
      subject: new Did(Uint8Array.from(Array(33).fill(0xcc))),
      command: new Command(["nil", "db", "read"]),
      notBefore: Temporal.Instant.fromEpochMilliseconds(1740494955000),
      expiresAt: Temporal.Instant.fromEpochMilliseconds(1740495955000),
      nonce: "010203",
      meta: { name: "bob" },
      body: new DelegationBody([]),
      proofs: [],
    });
    expect(envelope.token.token).toStrictEqual(expectedToken);
  });

  it("chain", ({ expect }) => {
    const rootKey = secp256k1.utils.randomPrivateKey();
    const rootToken = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".foo"), 42),
    ])
      .audience(new Did(Uint8Array.from(Array(33).fill(0xbb))))
      .subject(new Did(Uint8Array.from(Array(33).fill(0xcc))))
      .command(new Command(["nil", "db", "read"]))
      .build(rootKey);
    const root = NucTokenEnvelopeSchema.parse(rootToken);
    root.validateSignatures();

    const otherKey = secp256k1.utils.randomPrivateKey();
    const otherToken = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".foo"), 42),
    ])
      .audience(new Did(Uint8Array.from(Array(33).fill(0xbb))))
      .subject(new Did(Uint8Array.from(Array(33).fill(0xcc))))
      .command(new Command(["nil", "db", "read"]))
      .proof(root)
      .build(otherKey);
    const delegation = NucTokenEnvelopeSchema.parse(otherToken);
    delegation.validateSignatures();

    expect(delegation.token.token.proofs).toStrictEqual([
      root.token.computeHash(),
    ]);
    expect(delegation.proofs.length).toBe(1);
    expect(delegation.proofs[0]).toStrictEqual(root.token);

    const yetAnotherKey = secp256k1.utils.randomPrivateKey();
    const yetAnotherToken = NucTokenBuilder.invocation({ beep: 42 })
      .audience(new Did(Uint8Array.from(Array(33).fill(0xbb))))
      .subject(new Did(Uint8Array.from(Array(33).fill(0xcc))))
      .command(new Command(["nil", "db", "read"]))
      .proof(delegation)
      .build(yetAnotherKey);
    const invocation = NucTokenEnvelopeSchema.parse(yetAnotherToken);
    invocation.validateSignatures();

    expect(invocation.token.token.proofs).toStrictEqual([
      delegation.token.computeHash(),
    ]);
    expect(invocation.proofs.length).toBe(2);
    expect(invocation.proofs[0]).toStrictEqual(delegation.token);
    expect(invocation.proofs[1]).toStrictEqual(root.token);
  });

  it("decode specific", () => {
    const token =
      "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAyMjZhNGQ0YTRhNWZhZGUxMmM1ZmYwZWM5YzQ3MjQ5ZjIxY2Y3N2EyMDI3NTFmOTU5ZDVjNzc4ZjBiNjUyYjcxNiIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJhcmdzIjp7ImZvbyI6NDJ9LCJub25jZSI6IjAxMDIwMyIsInByZiI6WyJjOTA0YzVhMWFiMzY5YWVhMWI0ZDlkMTkwMmE0NmU2ZWY5NGFhYjk2OTY0YmI1MWQ2MWE2MWIwM2UyM2Q1ZGZmIl19.ufDYxqoSVNVETrVKReu0h_Piul5c6RoC_VnGGLw04mkyn2OMrtQjK92sGXNHCjlp7T9prIwxX14ZB_N3gx7hPg/eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAzNmY3MDdmYmVmMGI3NTIxMzgwOGJiYmY1NGIxODIxNzZmNTMyMGZhNTIwY2I4MTlmMzViNWJhZjIzMjM4YTAxNSIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJwb2wiOltbIj09IiwiLmZvbyIsNDJdXSwibm9uY2UiOiIwMTAyMDMiLCJwcmYiOlsiODZjZGI1ZjZjN2M3NDFkMDBmNmI4ODMzZDI0ZjdlY2Y5MWFjOGViYzI2MzA3MmZkYmU0YTZkOTQ5NzIwMmNiNCJdfQ.drGzkA0hYP8h62GxNN3fhi9bKjYgjpSy4cM52-9RsyB7JD6O6K1wRsg_x1hv8ladPmChpwDVVXOzjNr2NRVntA/eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAzOTU5MGNjYWYxMDI0ZjQ5YzljZjc0M2Y4YTZlZDQyMDNlNzgyZThlZTA5YWZhNTNkMWI1NzY0OTg0NjEyMzQyNSIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJwb2wiOltbIj09IiwiLmZvbyIsNDJdXSwibm9uY2UiOiIwMTAyMDMiLCJwcmYiOltdfQ.o3lnQxCjDCW10UuRABrHp8FpB_C6q1xgEGvfuXTb7Epp63ry8R2h0wHjToDKDFmkmUmO2jcBkrttuy8kftV6og";
    NucTokenEnvelopeSchema.parse(token).validateSignatures();
  });
});
