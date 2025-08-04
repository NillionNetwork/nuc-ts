import { create } from "@bufbuild/protobuf";
import { SigningStargateClient } from "@cosmjs/stargate";
import { z } from "zod";
import { Log } from "#/core/logger";
import { MsgPayForSchema } from "#/services/payer/gen/tx_pb";
import {
  GasLimitSchema,
  NilChainAddress,
  NilChainProtobufTypeUrl,
  TxHash,
} from "#/services/payer/types";

export const PayerConfigSchema = z.object({
  address: NilChainAddress,
  // SigningStargateClient's constructor is protected so we cannot use `z.instanceof()`
  client: z.custom<SigningStargateClient>(
    (v) => v instanceof SigningStargateClient,
  ),
  gasLimit: GasLimitSchema,
});
/**
 * Payer configuration.
 *
 * @property {string} address  Nilchain address.
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
   * @param config Payer configuration.
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

    try {
      const result = await this.config.client.signAndBroadcast(
        this.config.address,
        [{ typeUrl: NilChainProtobufTypeUrl, value }],
        this.config.gasLimit,
      );

      const hash = TxHash.parse(result.transactionHash);
      Log.info(
        { txHash: hash, amount: amountUnil },
        "Payment transaction successful",
      );
      return hash;
    } catch (error) {
      Log.error(`Pay failed: ${error}`);
      throw error;
    }
  }
}
