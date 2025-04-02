import { secp256k1 } from "@noble/curves/secp256k1";
import { Temporal } from "temporal-polyfill";
import { describe, it } from "vitest";
import { NucTokenBuilder } from "#/builder";
import { type NucTokenEnvelope, NucTokenEnvelopeSchema } from "#/envelope";
import { And, AnyOf, Equals, Not, Or, type Policy } from "#/policy";
import { Selector } from "#/selector";
import { Command, Did } from "#/token";
import { base64UrlDecodeToBytes, base64UrlEncode, pairwise } from "#/utils";
import {
  CHAIN_TOO_LONG,
  COMMAND_NOT_ATTENUATED,
  DIFFERENT_SUBJECTS,
  DelegationRequirement,
  INVALID_AUDIENCE,
  INVALID_SIGNATURES,
  ISSUER_AUDIENCE_MISMATCH,
  InvocationRequirement,
  MISSING_PROOF,
  NEED_DELEGATION,
  NEED_INVOCATION,
  NOT_BEFORE_BACKWARDS,
  NOT_BEFORE_NOT_MET,
  NucTokenValidator,
  POLICY_NOT_MET,
  POLICY_TOO_DEEP,
  POLICY_TOO_WIDE,
  PROOFS_MUST_BE_DELEGATIONS,
  PolicyTreeProperties,
  ROOT_KEY_SIGNATURE_MISSING,
  SUBJECT_NOT_IN_CHAIN,
  TOKEN_EXPIRED,
  UNCHAINED_PROOFS,
  ValidationParameters,
} from "#/validate";

const ROOT_KEYS = [secp256k1.utils.randomPrivateKey()];
const ROOT_DIDS = ROOT_KEYS.map(didFromPrivateKey);

class SignableNucTokenBuilder {
  constructor(
    public key: Uint8Array,
    public builder: NucTokenBuilder,
  ) {}

  build(): string {
    return this.builder.build(this.key);
  }

  static issuedByRoot(builder: NucTokenBuilder): SignableNucTokenBuilder {
    return new SignableNucTokenBuilder(ROOT_KEYS[0], builder);
  }
}

class Chainer {
  constructor(private readonly chainIssuerAudience: boolean = true) {}

  chain(builders: Array<SignableNucTokenBuilder>): NucTokenEnvelope {
    if (this.chainIssuerAudience) {
      for (const [previous, current] of pairwise(builders)) {
        const issuerKey = secp256k1.getPublicKey(current.key);
        previous.builder = previous.builder.audience(new Did(issuerKey));
      }
    }

    let envelope = NucTokenEnvelopeSchema.parse(builders[0].build());
    for (const builder of builders.slice(1)) {
      builder.builder = builder.builder.proof(envelope);
      envelope = NucTokenEnvelopeSchema.parse(builder.build());
    }
    return envelope;
  }
}

class Asserter {
  constructor(
    private readonly parameters: ValidationParameters = new ValidationParameters(),
  ) {}

  assertFailure(envelope: NucTokenEnvelope, message: string) {
    Asserter.log_tokens(envelope);
    const validator = new NucTokenValidator(ROOT_DIDS);
    try {
      validator.validate(envelope, this.parameters);
    } catch (e) {
      if (e instanceof Error) {
        if (e.message === message) {
          return;
        }
        throw new Error(`unexpected failed: ${e.message}`);
      }
    }
    throw new Error("did not fail");
  }

  assertSuccess(envelope: NucTokenEnvelope) {
    Asserter.log_tokens(envelope);
    const validator = new NucTokenValidator(ROOT_DIDS);
    validator.validate(envelope, this.parameters);
  }

  static log_tokens(envelope: NucTokenEnvelope) {
    console.log(`token being asserted: ${envelope.token.token.toString()}`);
    console.log(
      `proofs for it: ${envelope.proofs.map((proof) => proof.token.toString())}`,
    );
  }
}

function didFromPrivateKey(key: Uint8Array): Did {
  return new Did(secp256k1.getPublicKey(key));
}

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
    policy: new Equals(new Selector(["field"]), 42),
    expected: new PolicyTreeProperties({ maxDepth: 1, maxWidth: 1 }),
  },
  {
    policy: new AnyOf(new Selector(["field"]), [42, 1337]),
    expected: new PolicyTreeProperties({ maxDepth: 1, maxWidth: 2 }),
  },
  {
    policy: new Not(new Equals(new Selector(["field"]), 42)),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 1 }),
  },
  {
    policy: new And([new Equals(new Selector(["field"]), 42)]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 1 }),
  },
  {
    policy: new Or([new Equals(new Selector(["field"]), 42)]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 1 }),
  },
  {
    policy: new And([
      new Equals(new Selector(["field"]), 42),
      new Equals(new Selector(["field"]), 42),
    ]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 2 }),
  },
  {
    policy: new Or([
      new Equals(new Selector(["field"]), 42),
      new Equals(new Selector(["field"]), 42),
    ]),
    expected: new PolicyTreeProperties({ maxDepth: 2, maxWidth: 2 }),
  },
  {
    policy: new And([
      new Not(new Equals(new Selector(["field"]), 42)),
      new AnyOf(new Selector(["field"]), [42, 1337]),
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

    const parameters = new ValidationParameters();
    parameters.config.maxChainLength = 2;
    new Asserter(parameters).assertFailure(envelope, CHAIN_TOO_LONG);
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

    const parameters = new ValidationParameters();
    parameters.config.tokenRequirements = new InvocationRequirement(
      expectedDid,
    );
    new Asserter(parameters).assertFailure(envelope, INVALID_AUDIENCE);
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

    const parameters = new ValidationParameters();
    parameters.config.tokenRequirements = new DelegationRequirement(
      expectedDid,
    );
    new Asserter(parameters).assertFailure(envelope, INVALID_AUDIENCE);
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

    const parameters = new ValidationParameters();
    parameters.config.tokenRequirements = new DelegationRequirement(
      new Did(Uint8Array.from(Array(33).fill(0xaa))),
    );
    new Asserter(parameters).assertFailure(envelope, NEED_DELEGATION);
  });

  it("need invocation", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    const parameters = new ValidationParameters();
    parameters.config.tokenRequirements = new InvocationRequirement(
      new Did(Uint8Array.from(Array(33).fill(0xaa))),
    );
    new Asserter(parameters).assertFailure(envelope, NEED_INVOCATION);
  });

  it("not before backwards", () => {
    const now = Temporal.Now.instant();
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key)
      .command(new Command(["nil"]))
      .notBefore(Temporal.Instant.fromEpochSeconds(5));
    const last = delegation(key)
      .command(new Command(["nil"]))
      .notBefore(Temporal.Instant.fromEpochSeconds(3));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    const parameters = new ValidationParameters();
    parameters.config.currentTime = now;
    new Asserter(parameters).assertFailure(envelope, NOT_BEFORE_BACKWARDS);
  });

  it("not before not met", () => {
    const now = Temporal.Instant.fromEpochMilliseconds(0);
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key)
      .command(new Command(["nil"]))
      .notBefore(Temporal.Instant.fromEpochSeconds(10));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);

    const parameters = new ValidationParameters();
    parameters.config.currentTime = now;
    new Asserter(parameters).assertFailure(envelope, NOT_BEFORE_NOT_MET);
  });

  it("root policy not met", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(key);
    const root = NucTokenBuilder.delegation([
      new Equals(new Selector(["foo"]), 42),
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
      new Equals(new Selector(["foo"]), 42),
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
    let policy: Policy = new Equals(new Selector(["foo"]), 42);
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
    const parameters = new ValidationParameters();
    parameters.config.maxPolicyDepth = maxDepth;
    new Asserter(parameters).assertFailure(envelope, POLICY_TOO_DEEP);
  });

  it("policy too wide", () => {
    const maxWidth = 10;
    const key = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(key);
    const root = NucTokenBuilder.delegation(
      Array(maxWidth + 1).fill(new Equals(new Selector(["foo"]), 42)),
    )
      .subject(subject)
      .command(new Command(["nil"]));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    const parameters = new ValidationParameters();
    parameters.config.maxPolicyWidth = maxWidth;
    new Asserter(parameters).assertFailure(envelope, POLICY_TOO_WIDE);
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
      .expiresAt(Temporal.Instant.fromEpochSeconds(5));
    const last = delegation(key).command(new Command(["nil"]));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    const parameters = new ValidationParameters();
    parameters.config.currentTime = Temporal.Instant.fromEpochSeconds(10);
    new Asserter().assertFailure(envelope, TOKEN_EXPIRED);
  });

  it("last token expired", () => {
    const key = secp256k1.utils.randomPrivateKey();
    const root = delegation(key).command(new Command(["nil"]));
    const last = delegation(key)
      .command(new Command(["nil"]))
      .expiresAt(Temporal.Instant.fromEpochSeconds(5));
    const envelope = new Chainer().chain([
      SignableNucTokenBuilder.issuedByRoot(root),
      new SignableNucTokenBuilder(key, last),
    ]);
    const parameters = new ValidationParameters();
    parameters.config.currentTime = Temporal.Instant.fromEpochSeconds(10);
    new Asserter().assertFailure(envelope, TOKEN_EXPIRED);
  });

  it("valid", () => {
    const subjectKey = secp256k1.utils.randomPrivateKey();
    const subject = didFromPrivateKey(subjectKey);
    const rpcDid = new Did(new Uint8Array(Array(33).fill(33)));
    const root = NucTokenBuilder.delegation([
      new Equals(new Selector(["args", "foo"]), 42),
    ])
      .subject(subject)
      .command(new Command(["nil"]));
    const intermediate = NucTokenBuilder.delegation([
      new Equals(new Selector(["args", "bar"]), 1337),
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
    const parameters = new ValidationParameters();
    parameters.config.tokenRequirements = new InvocationRequirement(rpcDid);
    new Asserter(parameters).assertSuccess(envelope);
  });
});
