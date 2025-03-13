import { Temporal } from "temporal-polyfill";
import { describe, it } from "vitest";
import { Selector } from "#/selector";
import {
  Command,
  CommandSchema,
  DelegationBody,
  Did,
  DidSchema,
  InvocationBody,
  NucToken,
  NucTokenSchema,
} from "#/token";

describe.each([
  { test: "root", input: "/", expected: { segments: [] } },
  { test: "one", input: "/nil", expected: { segments: ["nil"] } },
  { test: "two", input: "/nil/bar", expected: { segments: ["nil", "bar"] } },
])("valid commands", ({ test, input, expected }) => {
  it(`${test}`, ({ expect }) => {
    const result = CommandSchema.parse(input);
    expect(result).toEqual(expected);
  });
});

describe.each([
  { test: "empty", input: "" },
  { test: "leading double slash", input: "//nil" },
  { test: "trailing slash", input: "/nil/" },
  { test: "double slash in middle", input: "/nil//a" },
])("invalid commands", ({ test, input }) => {
  it(`${test}`, ({ expect }) => {
    expect(() => CommandSchema.parse(input)).toThrowError();
  });
});

describe("valid did", () => {
  it("valid did", ({ expect }) => {
    const input =
      "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const did = DidSchema.parse(input);
    expect(did.publicKey).toEqual(
      new Uint8Array([
        170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
        170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
        170, 170, 170, 170, 170,
      ]),
    );
    expect(did.toString()).toEqual(input);
  });
});

describe.each([
  { input: "foo:bar:aa" },
  { input: "did:bar" },
  { input: "did:bar:aa:" },
  { input: "did:bar:lol" },
  {
    input:
      "did:test:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  },
])("invalid did", ({ input }) => {
  it(`${input}`, ({ expect }) => {
    expect(() => DidSchema.parse(input)).toThrowError();
  });
});

describe("parse token", () => {
  it("parse minimal delegation", ({ expect }) => {
    const data = {
      iss: "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      aud: "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      sub: "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      cmd: "/nil/db/read",
      pol: [["==", ".foo", 42]],
      nonce: "beef",
    };
    const token = NucTokenSchema.parse(data);
    const expected = new NucToken({
      issuer: new Did(
        new Uint8Array([
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170,
        ]),
      ),
      audience: new Did(
        new Uint8Array([
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187,
        ]),
      ),
      subject: new Did(
        new Uint8Array([
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204,
        ]),
      ),
      command: new Command(["nil", "db", "read"]),
      body: new DelegationBody([
        { type: "equals", selector: new Selector(["foo"]), value: 42 },
      ]),
      nonce: new Uint8Array([190, 239]),
      proofs: [],
      notBefore: undefined,
      expiresAt: undefined,
      meta: undefined,
    });
    expect(token).toStrictEqual(expected);
  });

  it("parse full delegation", ({ expect }) => {
    const data = {
      iss: "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      aud: "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      sub: "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      nbf: 1740494955,
      exp: 1740495955,
      cmd: "/nil/db/read",
      pol: [["==", ".foo", 42]],
      meta: {
        name: "bob",
      },
      nonce: "beef",
      prf: ["f4f04af6a832bcd8a6855df5d0242c9a71e9da17faeb2d33b30c8903f1b5a944"],
    };
    const token = NucTokenSchema.parse(data);
    const expected = new NucToken({
      issuer: new Did(
        new Uint8Array([
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170,
        ]),
      ),
      audience: new Did(
        new Uint8Array([
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187,
        ]),
      ),
      subject: new Did(
        new Uint8Array([
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204,
        ]),
      ),
      command: new Command(["nil", "db", "read"]),
      body: new DelegationBody([
        { type: "equals", selector: new Selector(["foo"]), value: 42 },
      ]),
      nonce: new Uint8Array([190, 239]),
      proofs: [
        new Uint8Array([
          244, 240, 74, 246, 168, 50, 188, 216, 166, 133, 93, 245, 208, 36, 44,
          154, 113, 233, 218, 23, 250, 235, 45, 51, 179, 12, 137, 3, 241, 181,
          169, 68,
        ]),
      ],
      notBefore: Temporal.Instant.fromEpochMilliseconds(1740494955),
      expiresAt: Temporal.Instant.fromEpochMilliseconds(1740495955),
      meta: { name: "bob" },
    });
    expect(token).toStrictEqual(expected);
  });

  it("parse minimal invocation", ({ expect }) => {
    const data = {
      iss: "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      aud: "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      sub: "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      cmd: "/nil/db/read",
      args: { bar: 42 },
      nonce: "beef",
    };
    const token = NucTokenSchema.parse(data);
    const expected = new NucToken({
      issuer: new Did(
        new Uint8Array([
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170,
        ]),
      ),
      audience: new Did(
        new Uint8Array([
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187,
        ]),
      ),
      subject: new Did(
        new Uint8Array([
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204,
        ]),
      ),
      command: new Command(["nil", "db", "read"]),
      body: new InvocationBody({ bar: 42 }),
      nonce: new Uint8Array([190, 239]),
      proofs: [],
      notBefore: undefined,
      expiresAt: undefined,
      meta: undefined,
    });
    expect(token).toStrictEqual(expected);
  });

  it("parse full invocation", ({ expect }) => {
    const data = {
      iss: "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      aud: "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      sub: "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      nbf: 1740494955,
      exp: 1740495955,
      cmd: "/nil/db/read",
      args: { bar: 42 },
      meta: {
        name: "bob",
      },
      nonce: "beef",
      prf: ["f4f04af6a832bcd8a6855df5d0242c9a71e9da17faeb2d33b30c8903f1b5a944"],
    };
    const token = NucTokenSchema.parse(data);
    const expected = new NucToken({
      issuer: new Did(
        new Uint8Array([
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
          170, 170, 170, 170, 170,
        ]),
      ),
      audience: new Did(
        new Uint8Array([
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
          187, 187, 187, 187, 187,
        ]),
      ),
      subject: new Did(
        new Uint8Array([
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204,
          204, 204, 204, 204, 204,
        ]),
      ),
      command: new Command(["nil", "db", "read"]),
      body: new InvocationBody({ bar: 42 }),
      nonce: new Uint8Array([190, 239]),
      proofs: [
        new Uint8Array([
          244, 240, 74, 246, 168, 50, 188, 216, 166, 133, 93, 245, 208, 36, 44,
          154, 113, 233, 218, 23, 250, 235, 45, 51, 179, 12, 137, 3, 241, 181,
          169, 68,
        ]),
      ],
      notBefore: Temporal.Instant.fromEpochMilliseconds(1740494955),
      expiresAt: Temporal.Instant.fromEpochMilliseconds(1740495955),
      meta: { name: "bob" },
    });
    expect(token).toStrictEqual(expected);
  });

  it("parse mixed delegation invocation", ({ expect }) => {
    const data = {
      iss: "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      aud: "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      sub: "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      cmd: "/nil/db/read",
      args: { bar: 42 },
      pol: [["==", ".foo", 42]],
      nonce: "beef",
    };
    expect(() => NucTokenSchema.parse(data)).toThrowError;
  });

  it("parse no delegation invocation", ({ expect }) => {
    const data = {
      iss: "did:nil:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      aud: "did:nil:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      sub: "did:nil:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      cmd: "/nil/db/read",
      nonce: "beef",
    };
    expect(() => NucTokenSchema.parse(data)).toThrowError;
  });
});
