import {
  DirectSecp256k1Wallet,
  type OfflineSigner,
} from "@cosmjs/proto-signing";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { NilChainAddressPrefix, type PrivateKeyBase16 } from "./types";

export class Wallet {
  public readonly privateKey: string;
  public readonly publicKey: string;
  constructor(privateKey: string | Uint8Array) {
    this.privateKey =
      typeof privateKey === "string" ? privateKey : bytesToHex(privateKey);
    this.publicKey = bytesToHex(secp256k1.getPublicKey(this.privateKey));
  }

  privateKeyAsBytes(): Uint8Array {
    return hexToBytes(this.privateKey);
  }

  publicKeyAsBytes(): Uint8Array {
    return hexToBytes(this.publicKey);
  }

  async signer(): Promise<OfflineSigner> {
    return createSignerFromKey(this.privateKey);
  }

  static generate(): Wallet {
    return new Wallet(secp256k1.utils.randomPrivateKey());
  }
}

const createSignerFromKey = async (
  key: PrivateKeyBase16 | string,
): Promise<OfflineSigner> => {
  const privateKey = new Uint8Array(key.length / 2);
  for (let i = 0, j = 0; i < key.length; i += 2, j++) {
    privateKey[j] = Number.parseInt(key.slice(i, i + 2), 16);
  }
  return await DirectSecp256k1Wallet.fromKey(privateKey, NilChainAddressPrefix);
};
