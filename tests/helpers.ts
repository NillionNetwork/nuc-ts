import process from "node:process";

export const Env = {
  nilChainUrl: process.env.NILLION_NILCHAIN_JSON_RPC ?? "",
  nilChainPrivateKey0: process.env.NILLION_NILCHAIN_PRIVATE_KEY_0 ?? "",
  nilChainPrivateKey1: process.env.NILLION_NILCHAIN_PRIVATE_KEY_1 ?? "",
};

export const PrivateKeyPerSuite = {
  Payer: Env.nilChainPrivateKey0,
  Authority: Env.nilChainPrivateKey1,
};
