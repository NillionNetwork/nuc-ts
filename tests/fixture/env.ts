import process from "node:process";

export const Env = {
  nilChainUrl: process.env.NILLION_NILCHAIN_JSON_RPC ?? "",
  Payer: process.env.NILLION_NILCHAIN_PRIVATE_KEY_0 ?? "",
  AuthorityService: process.env.NILLION_NILCHAIN_PRIVATE_KEY_1 ?? "",
};
