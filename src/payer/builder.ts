import {
  DirectSecp256k1Wallet,
  type OfflineSigner,
  Registry,
} from "@cosmjs/proto-signing";
import { GasPrice, SigningStargateClient } from "@cosmjs/stargate";
import { z } from "zod";
import { Keypair } from "#/keypair";
import { Payer, PayerConfigSchema } from "#/payer/client";
import { MsgPayForCompatWrapper } from "#/payer/grpc-compat";
import {
  type GasLimit,
  GasLimitSchema,
  NilChainAddressPrefix,
  NilChainProtobufTypeUrl,
  NilToken,
} from "#/payer/types";

const PayerBuilderConfig = z.object({
  keypair: z.instanceof(Keypair),
  chainUrl: z.string().url("Invalid chain url"),
  gasLimit: GasLimitSchema,
  broadcastTimeoutMs: z.number(),
  broadcastPollIntervalMs: z.number(),
});

export class PayerBuilder {
  private _keypair?: Keypair;
  private _chainUrl?: string;
  private _gasLimit: GasLimit = "auto";
  private _broadcastTimeoutMs = 30000;
  private _broadcastPollIntervalMs = 1000;

  keypair(keypair: Keypair): this {
    this._keypair = keypair;
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
      keypair,
      chainUrl,
      gasLimit,
      broadcastTimeoutMs,
      broadcastPollIntervalMs,
    } = PayerBuilderConfig.parse({
      keypair: this._keypair,
      chainUrl: this._chainUrl,
      gasLimit: this._gasLimit,
      broadcastTimeoutMs: this._broadcastTimeoutMs,
      broadcastPollIntervalMs: this._broadcastPollIntervalMs,
    });

    const signer = await createSignerFromKeyPair(keypair);
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

export async function createSignerFromKeyPair(
  keypair: Keypair,
): Promise<OfflineSigner> {
  return await DirectSecp256k1Wallet.fromKey(
    keypair.privateKey(),
    NilChainAddressPrefix,
  );
}
