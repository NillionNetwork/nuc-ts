import { create } from "@bufbuild/protobuf";
import { SigningStargateClient } from "@cosmjs/stargate";
import { Effect as E, pipe } from "effect";
import { z } from "zod";
import { MsgPayForSchema } from "#/gen-proto/nillion/meta/v1/tx_pb";
import {
  GasLimitSchema,
  NilChainAddress,
  NilChainProtobufTypeUrl,
  TxHash,
} from "#/payer/types";

export const PayerConfigSchema = z.object({
  address: NilChainAddress,
  client: z.custom<SigningStargateClient>(
    (value: unknown) => value instanceof SigningStargateClient,
  ),
  gasLimit: GasLimitSchema,
});
export type PayerConfig = z.infer<typeof PayerConfigSchema>;

export class Payer {
  constructor(private readonly config: PayerConfig) {}

  async pay(resource: Uint8Array, amountUnil: number): Promise<TxHash> {
    const value = create(MsgPayForSchema, {
      resource,
      fromAddress: this.config.address,
      amount: [{ denom: "unil", amount: String(amountUnil) }],
    });
    return pipe(
      E.tryPromise(() =>
        this.config.client.signAndBroadcast(
          this.config.address,
          [{ typeUrl: NilChainProtobufTypeUrl, value }],
          this.config.gasLimit,
        ),
      ),
      E.flatMap((result) => E.try(() => TxHash.parse(result.transactionHash))),
      E.catchAll((e) => E.fail(e.cause)),
      // TODO Replace console.log with logger
      E.tapBoth({
        onSuccess: (hash) =>
          E.sync(() => console.log(`Paid ${amountUnil} unil hash: ${hash}`)),
        onFailure: (e) => E.sync(() => console.log(`Pay failed: ${e}`)),
      }),
      E.runPromise,
    );
  }
}
