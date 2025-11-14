import { create } from "@bufbuild/protobuf";
import { type BinaryReader, BinaryWriter } from "@bufbuild/protobuf/wire";
import type { TsProtoGeneratedType } from "@cosmjs/proto-signing";
import { type MsgPayFor, MsgPayForSchema } from "#/services/payer/gen/tx_pb";

/**
 * Compatibility bridge between @bufbuild/protobuf (used by our library) and protobuf.js (used by CosmJS).
 *
 * This file exists solely to handle the incompatibility between two protobuf implementations:
 * - Our library uses the modern @bufbuild/protobuf package
 * - CosmJS still depends on the older protobuf.js package
 *
 * This wrapper maintains API compatibility with the cosmjs library while using `@bufbuild/protobuf`.
 * It bridges the gap between different protobuf implementations during the migration from
 * protobufjs to `@bufbuild/protobuf` and from the cluster's migration from libp2p to gRPC.
 *
 * Only `encode` and `fromPartial` methods are implemented as they are sufficient for sending transactions.
 *
 * We use `@ts-expect-error` because `TsProtoGeneratedType` expects `protobuf.Writer/Reader`,
 * but we're using `BinaryWriter/Reader`. The methods used are compatible between these types,
 * allowing us to bypass the type check safely in this context.
 *
 * TODO: This entire file can be removed once CosmJS updates to @bufbuild/protobuf or provides
 * a compatibility layer. Track progress at: https://github.com/cosmos/cosmjs/issues
 */
export const MsgPayForCompatWrapper: TsProtoGeneratedType = {
  encode: (
    message: MsgPayFor,
    writer: BinaryWriter = new BinaryWriter(),
  ): BinaryWriter => {
    if (message.resource.length > 0) {
      writer.uint32(10).bytes(message.resource);
    }
    if (message.fromAddress !== "") {
      writer.uint32(18).string(message.fromAddress);
    }
    for (const amount of message.amount) {
      const amountWriter = new BinaryWriter();
      if (amount.denom !== "") {
        amountWriter.uint32(10).string(amount.denom);
      }
      if (amount.amount !== "") {
        amountWriter.uint32(18).string(amount.amount);
      }
      writer.uint32(26).bytes(amountWriter.finish());
    }
    return writer;
  },
  decode: (_input: BinaryReader | Uint8Array, _length?: number): MsgPayFor => {
    throw new Error("MsgPayForCompatWrapper: decode not implemented");
  },
  fromPartial: (object: Partial<MsgPayFor>): MsgPayFor => {
    return create(MsgPayForSchema, {
      resource: object.resource,
      fromAddress: object.fromAddress,
      amount: object.amount,
    });
  },
};
