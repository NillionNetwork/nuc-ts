import { create } from "@bufbuild/protobuf";
import { SigningStargateClient } from "@cosmjs/stargate";
import { Effect as E, pipe } from "effect";
import { z } from "zod";
import { MsgPayForSchema } from "#/gen-proto/nillion/meta/v1/tx_pb";
import { log } from "#/logger";
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
/**
 * Payer configuration.
 *
 * @property {string} address  Nilchain address
 * @property {SigningStargateClient} client Cosmos client to perform transactions in nilchain
 * @property {string} gasLimit Gas limit strategy auto a fixed value are allowed.
 */
export type PayerConfig = z.infer<typeof PayerConfigSchema>;

/**
 * A payer that allows making payments on nilchain.
 */
export class Payer {
  /**
   * Creates a Payer instance for the given configuration.
   *
   * @param config Payer configuration
   */
  constructor(private readonly config: PayerConfig) {}

  /**
   * Peform a 'MsgPayFor' payment for the given resource.
   *
   * @param resource The resource to use in the transaction.
   * @param amountUnil The amount of unil to send in the payment.
   */
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
      E.tapBoth({
        onSuccess: (hash) =>
          E.sync(() => log(`Paid ${amountUnil} unil hash: ${hash}`)),
        onFailure: (e) => E.sync(() => log(`Pay failed: ${e}`)),
      }),
      E.runPromise,
    );
  }
}
