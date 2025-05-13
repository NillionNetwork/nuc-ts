import { secp256k1 } from "@noble/curves/secp256k1";
import type { NucTokenBuilder } from "#/builder";
import { type NucTokenEnvelope, NucTokenEnvelopeSchema } from "#/envelope";
import { Did } from "#/token";
import { pairwise } from "#/utils";
import { ROOT_KEYS } from "./assertions";

export class SignableNucTokenBuilder {
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

export class Chainer {
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
