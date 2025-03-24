import { type OfflineSigner, Registry } from "@cosmjs/proto-signing";
import { GasPrice, SigningStargateClient } from "@cosmjs/stargate";
import { z } from "zod";
import { Payer, PayerConfigSchema } from "#/payer/client";
import { MsgPayForCompatWrapper } from "#/payer/grpc-compat";
import {
  type GasLimit,
  GasLimitSchema,
  NilChainProtobufTypeUrl,
  NilToken,
  OfflineSignerSchema,
} from "#/payer/types";

const PayerBuilderConfig = z.object({
  signer: OfflineSignerSchema,
  chainUrl: z.string().url("Invalid chain url"),
  gasLimit: GasLimitSchema,
  broadcastTimeoutMs: z.number(),
  broadcastPollIntervalMs: z.number(),
});

export class PayerBuilder {
  private _signer?: OfflineSigner;
  private _chainUrl?: string;
  private _gasLimit: GasLimit = "auto";
  private _broadcastTimeoutMs = 30000;
  private _broadcastPollIntervalMs = 1000;

  signer(signer: OfflineSigner): this {
    this._signer = signer;
    return this;
  }

  chainUrl(url: string): this {
    this._chainUrl = url;
    return this;
  }

  gasLimit(gasLimit: GasLimit): this {
    this._gasLimit = gasLimit;
    return this;
  }

  broadcastTimeoutMs(broadcastTimeoutMs: number) {
    this._broadcastTimeoutMs = broadcastTimeoutMs;
    return this;
  }

  broadcastPollIntervalMs(broadcastPollIntervalMs: number) {
    this._broadcastPollIntervalMs = broadcastPollIntervalMs;
    return this;
  }

  async build(): Promise<Payer> {
    const {
      signer,
      chainUrl,
      gasLimit,
      broadcastTimeoutMs,
      broadcastPollIntervalMs,
    } = PayerBuilderConfig.parse({
      signer: this._signer,
      chainUrl: this._chainUrl,
      gasLimit: this._gasLimit,
      broadcastTimeoutMs: this._broadcastTimeoutMs,
      broadcastPollIntervalMs: this._broadcastPollIntervalMs,
    });

    const accounts = await signer.getAccounts();
    if (accounts.length === 0) {
      throw new Error("No accounts on the offline signer");
    }
    const address = accounts[0]?.address ?? "";

    const registry = new Registry();
    registry.register(NilChainProtobufTypeUrl, MsgPayForCompatWrapper);

    const client = await SigningStargateClient.connectWithSigner(
      z.string().url().parse(chainUrl),
      signer,
      {
        gasPrice: GasPrice.fromString(NilToken.asUnil(0.0)),
        registry,
        broadcastTimeoutMs,
        broadcastPollIntervalMs,
      },
    );

    const config = PayerConfigSchema.parse({
      address,
      client,
      gasLimit,
    });

    return new Payer(config);
  }
}
