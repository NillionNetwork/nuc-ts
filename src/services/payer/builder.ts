import {
  DirectSecp256k1Wallet,
  type OfflineSigner,
  Registry,
} from "@cosmjs/proto-signing";
import { GasPrice, SigningStargateClient } from "@cosmjs/stargate";
import type { Window as KeplrWindow } from "@keplr-wallet/types";
import { z } from "zod";
import type { Keypair } from "#/core/keypair";
import { Payer, PayerConfigSchema } from "#/services/payer/client";
import { MsgPayForCompatWrapper } from "#/services/payer/grpc-compat";
import {
  type GasLimit,
  NilChainAddressPrefix,
  NilChainProtobufTypeUrl,
  NilToken,
} from "#/services/payer/types";

declare global {
  interface Window extends KeplrWindow {}
}

/**
 * Payer builder.
 */
export class PayerBuilder {
  private _chainUrl?: string;
  private _gasLimit: GasLimit = "auto";
  private _broadcastTimeoutMs = 30000;
  private _broadcastPollIntervalMs = 1000;
  private _signerSource?:
    | { type: "keypair"; value: Keypair }
    | { type: "keplr"; chainId: string };

  private constructor() {}

  static fromKeypair(keypair: Keypair): PayerBuilder {
    const builder = new PayerBuilder();
    builder._signerSource = { type: "keypair", value: keypair };
    return builder;
  }

  static fromKeplr(chainId: string): PayerBuilder {
    const builder = new PayerBuilder();
    builder._signerSource = { type: "keplr", chainId };
    return builder;
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
    if (!this._signerSource) {
      throw new Error(
        "Signer source not configured. Use fromKeypair() or fromKeplr().",
      );
    }

    if (!this._chainUrl) {
      throw new Error("Chain URL not configured.");
    }

    let signer: OfflineSigner;
    let address: string;

    switch (this._signerSource.type) {
      case "keypair": {
        signer = await createSignerFromKeyPair(this._signerSource.value);
        const accounts = await signer.getAccounts();
        if (accounts.length === 0) {
          throw new Error("No accounts on the offline signer");
        }
        address = accounts[0]?.address ?? "";
        break;
      }
      case "keplr": {
        // Detect Keplr
        const win = globalThis as KeplrWindow;
        const { keplr } = win || {};
        if (!keplr) {
          throw new Error("You need to install Keplr");
        }

        // Create the signing client
        const offlineSigner = win.getOfflineSigner?.(
          this._signerSource.chainId,
        );
        if (!offlineSigner) {
          throw new Error("No offline signer found");
        }
        signer = offlineSigner;
        const accounts = await signer.getAccounts();
        if (accounts.length === 0) {
          throw new Error("No accounts on the offline signer");
        }
        address = accounts[0]?.address ?? "";
        break;
      }
    }

    const registry = new Registry();
    registry.register(NilChainProtobufTypeUrl, MsgPayForCompatWrapper);

    const client = await SigningStargateClient.connectWithSigner(
      z.url().parse(this._chainUrl),
      signer,
      {
        gasPrice: GasPrice.fromString(NilToken.asUnil(0.0)),
        registry,
        broadcastTimeoutMs: this._broadcastTimeoutMs,
        broadcastPollIntervalMs: this._broadcastPollIntervalMs,
      },
    );

    const config = PayerConfigSchema.parse({
      address,
      client,
      gasLimit: this._gasLimit,
    });

    return new Payer(config);
  }
}

async function createSignerFromKeyPair(
  keypair: Keypair,
): Promise<OfflineSigner> {
  return await DirectSecp256k1Wallet.fromKey(
    keypair.privateKeyBytes(),
    NilChainAddressPrefix,
  );
}
