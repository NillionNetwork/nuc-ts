import { secp256k1 } from "@noble/curves/secp256k1";
import { Temporal } from "temporal-polyfill";
import { describe, it } from "vitest";
import { NucTokenBuilder } from "#/builder";
import { NucTokenEnvelopeSchema } from "#/envelope";
import { Keypair } from "#/keypair";
import { And, AnyOf, Equals, Not, Or, type Policy } from "#/policy";
import { SelectorSchema } from "#/selector";
import { Command, Did, REVOKE_COMMAND } from "#/token";
import { base64UrlDecodeToBytes, base64UrlEncode } from "#/utils";
import {
  CHAIN_TOO_LONG,
  COMMAND_NOT_ATTENUATED,
  DelegationRequirement,
  DIFFERENT_SUBJECTS,
  INVALID_AUDIENCE,
  INVALID_SIGNATURES,
  InvocationRequirement,
  ISSUER_AUDIENCE_MISMATCH,
  MISSING_PROOF,
  NEED_DELEGATION,
  NEED_INVOCATION,
  NOT_BEFORE_BACKWARDS,
  NOT_BEFORE_NOT_MET,
  POLICY_NOT_MET,
  POLICY_TOO_DEEP,
  POLICY_TOO_WIDE,
  PolicyTreeProperties,
  PROOFS_MUST_BE_DELEGATIONS,
  ROOT_KEY_SIGNATURE_MISSING,
  SUBJECT_NOT_IN_CHAIN,
  TOKEN_EXPIRED,
  UNCHAINED_PROOFS,
  ValidationParameters,
} from "#/validate";
import { Asserter, didFromPrivateKey } from "./fixture/assertions";
import { Chainer, SignableNucTokenBuilder } from "./fixture/chainer";

function delegation(key: Uint8Array): NucTokenBuilder {
  return NucTokenBuilder.delegation([])
    .audience(new Did(Uint8Array.from(Array(33).fill(0xde))))
    .subject(didFromPrivateKey(key));
}

function invocation(key: Uint8Array): NucTokenBuilder {
  return NucTokenBuilder.invocation({})
    .audience(new Did(Uint8Array.from(Array(33).fill(0xde))))
    .subject(didFromPrivateKey(key));
}

describe.each([
  {
    policy: new Equals(SelectorSchema.parse(".field"), 42),
    expected: new PolicyTreeProperties({ maxDepth: 1, maxWidth: 1 }),
  },
  {
    policy: new AnyOf(SelectorSchema.parse(".field"), [42, 1337]),
    expected: new PolicyTreeProperties({ maxDepth: 1, maxWidth: 2 }),
  },
  {
    policy: new Not(new Equals(SelectorSchema.parse(".field"), 42)),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 1 }),
  },
  {
    policy: new And([new Equals(SelectorSchema.parse(".field"), 42)]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 1 }),
  },
  {
    policy: new Or([new Equals(SelectorSchema.parse(".field"), 42)]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 1 }),
  },
  {
    policy: new And([
      new Equals(SelectorSchema.parse(".field"), 42),
      new Equals(SelectorSchema.parse(".field"), 42),
    ]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 2 }),
  },
  {
    policy: new Or([
      new Equals(SelectorSchema.parse(".field"), 42),
      new Equals(SelectorSchema.parse(".field"), 42),
    ]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 2 }),
  },
  {
    policy: new And([
      new Not(new Equals(SelectorSchema.parse(".field"), 42)),
      new AnyOf(SelectorSchema.parse(".field"), [42, 1337]),
    ]),
    expected: new PolicyTreeProperties({ maxDepth: 3, maxWidth: 2 }),
  },
])("policy properties", ({ policy, expected }) => {
  it(`${policy.toString()}`, ({ expect }) => {
    expect(PolicyTreeProperties.fromPolicy(policy)).toStrictEqual(expected);
  });
});

describe("chain", () => {
  it("unlinked chain", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const base = delegation(key).command(new Command(["nil"]));
    const chain = new Chainer()
      .chain([
        SignableNucTokenBuilder.issuedByRoot(base),
        new SignableNucTokenBuilder(key, base),
      ])
      .serialize();

    const last = SignableNucTokenBuilder.issuedByRoot(base).build();
    const token = `${chain}/${last}`;
    const envelope = NucTokenEnvelopeSchema.parse(token);
    new Asserter().assertFailure(envelope, UNCHAINED_PROOFS);
  });

  it("chain too long", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const base = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(base),
      new SignableNucTokenBuilder(key, base),
      new SignableNucTokenBuilder(key, base),
    ]);

    const parameters = new ValidationParameters({ maxChainLength: 2 });
    new Asserter({ parameters }).assertFailure(envelope, CHAIN_TOO_LONG);
  });

  it("command not attenuated", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const last = delegation(key).command(new Command(["bar"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    new Asserter().assertFailure(envelope, COMMAND_NOT_ATTENUATED);
  });

  it("different subjects", () => {
    const key1 = secp256k1.utils.randomPrivateKey();
    const key2 = key1.slice();
    key2[0] ^= 1;
    const root = delegation(key1).command(new Command(["nil"]));
    const last = delegation(key2).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key2, last),
    ]);

    new Asserter().assertFailure(envelope, DIFFERENT_SUBJECTS);
  });

  it("audience mismatch", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key)
      .command(new Command(["nil"]))
      .audience(new Did(Uint8Array.from(Array(33).fill(0xaa))));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer(false).chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    new Asserter().assertFailure(envelope, ISSUER_AUDIENCE_MISMATCH);
  });

  it("invalid audience invocation", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const expectedDid = new Did(Uint8Array.from(Array(33).fill(0xaa)));
    const actualDid = new Did(Uint8Array.from(Array(33).fill(0xbb)));

    const root = delegation(key).command(new Command(["nil"]));
    const last = invocation(key)
      .command(new Command(["nil"]))
      .audience(actualDid);
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    const parameters = new ValidationParameters({
      tokenRequirements: new InvocationRequirement(expectedDid),
    });
    new Asserter({ parameters }).assertFailure(envelope, INVALID_AUDIENCE);
  });

  it("invalid audience delegation", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const expectedDid = new Did(Uint8Array.from(Array(33).fill(0xaa)));
    const actualDid = new Did(Uint8Array.from(Array(33).fill(0xbb)));

    const root = delegation(key).command(new Command(["nil"]));
    const last = delegation(key)
      .command(new Command(["nil"]))
      .audience(actualDid);
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    const tokenRequirements = new DelegationRequirement(expectedDid);
    const parameters = new ValidationParameters({ tokenRequirements });
    new Asserter({ parameters }).assertFailure(envelope, INVALID_AUDIENCE);
  });

  it("invalid signature", () => {
    const key = secp256k1.utils.randomPrivateKey();

    const root = delegation(key).command(new Command(["nil"]));
    let envelope = new Chainer()
      .chain([SignableNucTokenBuilder.issuedByRoot(root)])
      .serialize();

    const [header, payload, signature] = envelope.split(".");
    const invalidSignature = base64UrlDecodeToBytes(signature);
    invalidSignature[0] ^= 1;

    envelope = `${header}.${payload}.${base64UrlEncode(invalidSignature)}`;
    new Asserter().assertFailure(
      NucTokenEnvelopeSchema.parse(envelope),
      INVALID_SIGNATURES,
    );
  });

  it("missing proof", () => {
    const key = secp256k1.utils.randomPrivateKey();

    const base = delegation(key).command(new Command(["nil"]));
    let envelope = new Chainer()
      .chain([
        SignableNucTokenBuilder.issuedByRoot(base),
        new SignableNucTokenBuilder(key, base),
      ])
      .serialize();

    envelope = envelope.split("/")[0];
    new Asserter().assertFailure(
      NucTokenEnvelopeSchema.parse(envelope),
      MISSING_PROOF,
    );
  });

  it("need delegation", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const last = invocation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    const expectedDid = new Did(Uint8Array.from(Array(33).fill(0xaa)));
    const tokenRequirements = new DelegationRequirement(expectedDid);
    const parameters = new ValidationParameters({ tokenRequirements });
    new Asserter({ parameters }).assertFailure(envelope, NEED_DELEGATION);
  });

  it("need invocation", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    const expectedDid = new Did(Uint8Array.from(Array(33).fill(0xaa)));
    const tokenRequirements = new InvocationRequirement(expectedDid);
    const parameters = new ValidationParameters({ tokenRequirements });
    new Asserter({ parameters }).assertFailure(envelope, NEED_INVOCATION);
  });

  it("not before backwards", () => {
    const now = Temporal.Now.instant();
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key)
      .command(new Command(["nil"]))
      .notBefore(Temporal.Instant.fromEpochMilliseconds(5 * 1000));
    const last = delegation(key)
      .command(new Command(["nil"]))
      .notBefore(Temporal.Instant.fromEpochMilliseconds(3 * 1000));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    new Asserter({ currentTime: now }).assertFailure(
      envelope,
      NOT_BEFORE_BACKWARDS,
    );
  });

  it("not before not met", () => {
    const now = Temporal.Instant.fromEpochMilliseconds(0);
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key)
      .command(new Command(["nil"]))
      .notBefore(Temporal.Instant.fromEpochMilliseconds(10 * 1000));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    new Asserter({ currentTime: now }).assertFailure(
      envelope,
      NOT_BEFORE_NOT_MET,
    );
  });

  it("root policy not met", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(key);
    const root = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".foo"), 42),
    ])
      .subject(subject)
      .command(new Command(["nil"]));
    const last = NucTokenBuilder.invocation({ bar: 1337 })
      .subject(subject)
      .audience(new Did(new Uint8Array(Array(33).fill(0xaa))))
      .command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    new Asserter().assertFailure(envelope, POLICY_NOT_MET);
  });

  it("last policy not met", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(key);
    const root = NucTokenBuilder.delegation([])
      .subject(subject)
      .command(new Command(["nil"]));
    const intermediate = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".foo"), 42),
    ])
      .subject(subject)
      .command(new Command(["nil"]));
    const last = NucTokenBuilder.invocation({ bar: 1337 })
      .subject(subject)
      .audience(new Did(new Uint8Array(Array(33).fill(0xaa))))
      .command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, intermediate),
      new SignableNucTokenBuilder(key, last),
    ]);
    new Asserter().assertFailure(envelope, POLICY_NOT_MET);
  });

  it("policy too deep", () => {
    let policy: Policy = new Equals(SelectorSchema.parse(".foo"), 42);
    const maxDepth = 10;
    for (let i = 0; i < maxDepth; i++) {
      policy = new Not(policy);
    }

    const key = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(key);
    const root = NucTokenBuilder.delegation([policy])
      .subject(subject)
      .command(new Command(["nil"]));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    const parameters = new ValidationParameters({ maxPolicyDepth: maxDepth });
    new Asserter({ parameters }).assertFailure(envelope, POLICY_TOO_DEEP);
  });

  it("policy too wide", () => {
    const maxWidth = 10;
    const key = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(key);
    const root = NucTokenBuilder.delegation(
      Array(maxWidth + 1).fill(new Equals(SelectorSchema.parse(".foo"), 42)),
    )
      .subject(subject)
      .command(new Command(["nil"]));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    const parameters = new ValidationParameters({ maxPolicyWidth: maxWidth });
    new Asserter({ parameters }).assertFailure(envelope, POLICY_TOO_WIDE);
  });

  it("proofs must be delegations", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(key);
    const root = NucTokenBuilder.invocation({})
      .subject(subject)
      .command(new Command(["nil"]));
    const last = NucTokenBuilder.invocation({ bar: 1337 })
      .subject(subject)
      .audience(new Did(new Uint8Array(Array(33).fill(0xaa))))
      .command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    new Asserter().assertFailure(envelope, PROOFS_MUST_BE_DELEGATIONS);
  });

  it("root key signature missing", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      new SignableNucTokenBuilder(key, root),
      new SignableNucTokenBuilder(key, last),
    ]);
    new Asserter().assertFailure(envelope, ROOT_KEY_SIGNATURE_MISSING);
  });

  it("subject is not in chain", () => {
    const subjectKey = secp256k1.utils.randomPrivateKey();
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(subjectKey).command(new Command(["nil"]));
    const last = delegation(subjectKey).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    new Asserter().assertFailure(envelope, SUBJECT_NOT_IN_CHAIN);
  });

  it("root token expired", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key)
      .command(new Command(["nil"]))
      .expiresAt(Temporal.Instant.fromEpochMilliseconds(5 * 1000));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    new Asserter({
      currentTime: Temporal.Instant.fromEpochMilliseconds(10 * 1000),
    }).assertFailure(envelope, TOKEN_EXPIRED);
  });

  it("last token expired", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const last = delegation(key)
      .command(new Command(["nil"]))
      .expiresAt(Temporal.Instant.fromEpochMilliseconds(5 * 1000));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    new Asserter({
      currentTime: Temporal.Instant.fromEpochMilliseconds(10 * 1000),
    }).assertFailure(envelope, TOKEN_EXPIRED);
  });

  it("valid", () => {
    const subjectKey = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(subjectKey);
    const rpcDid = new Did(new Uint8Array(Array(33).fill(33)));
    const root = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".args.foo"), 42),
      new Equals(SelectorSchema.parse("$.req.bar"), 1337),
    ])
      .subject(subject)
      .command(new Command(["nil"]));
    const intermediate = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".args.bar"), 1337),
    ])
      .subject(subject)
      .command(new Command(["nil", "bar"]));

    const invocationKey = secp256k1.utils.randomPrivateKey();
    const invocation = NucTokenBuilder.invocation({ foo: 42, bar: 1337 })
      .subject(subject)
      .audience(rpcDid)
      .command(new Command(["nil", "bar", "foo"]));

    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(subjectKey, intermediate),
      new SignableNucTokenBuilder(invocationKey, invocation),
    ]);
    const parameters = new ValidationParameters({
      tokenRequirements: new InvocationRequirement(rpcDid),
    });
    new Asserter({ parameters, context: { req: { bar: 1337 } } }).assertSuccess(
      envelope,
    );
  });

  it("test valid revocation", () => {
    const subjectKey = Keypair.generate();
    const subject = subjectKey.toDid();
    const rpcDid = new Did(new Uint8Array(Array(33).fill(33)));
    const root = NucTokenBuilder.delegation([
      new Equals(SelectorSchema.parse(".args.foo"), 42),
    ])
      .subject(subject)
      .command(new Command(["nil"]));
    const invocation = NucTokenBuilder.invocation({ foo: 42, bar: 1337 })
      .subject(subject)
      .audience(rpcDid)
      .command(REVOKE_COMMAND);
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(subjectKey.privateKey(), invocation),
    ]);
    const parameters = new ValidationParameters({
      tokenRequirements: new InvocationRequirement(rpcDid),
    });
    new Asserter({ parameters }).assertSuccess(envelope);
  });

  it("test root token", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
    ]);
    new Asserter().assertSuccess(envelope);
  });

  it("test no root keys", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      new SignableNucTokenBuilder(key, root),
    ]);
    new Asserter({ rootDids: [] }).assertSuccess(envelope);
  });
});
