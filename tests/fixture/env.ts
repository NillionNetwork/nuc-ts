import process from "node:process";

export const Env = {
  nilAuthUrl: process.env.NILLION_NILAUTH_URL ?? "",
  nilChainUrl: process.env.NILLION_NILCHAIN_JSON_RPC ?? "",
  Payer: process.env.NILLION_NILCHAIN_PRIVATE_KEY_0 ?? "",
  NilauthClient: process.env.NILLION_NILCHAIN_PRIVATE_KEY_1 ?? "",
};
