import { z } from "zod";

export const GasLimitSchema = z.union([z.literal("auto"), z.number()]);
export type GasLimit = z.infer<typeof GasLimitSchema>;

export const TxHash = z.base64().length(64).brand<"TxHash">();
export type TxHash = z.infer<typeof TxHash>;

export const NilChainAddressPrefix = "nillion";
export const NilChainAddress = z
  .string()
  .length(46)
  .startsWith(NilChainAddressPrefix)
  .brand<"NilChainAddress">();
export type NilChainAddress = z.infer<typeof NilChainAddress>;

export const NilToken = {
  Unil: "unil",
  asUnil: (amount: number | string) => `${String(amount)}${NilToken.Unil}`,
};

export const NilChainProtobufTypeUrl = "/nillion.meta.v1.MsgPayFor";

export const PrivateKeyBase16 = z
  .string()
  .length(64)
  .brand<"PrivateKeyBase16">();
export type PrivateKeyBase16 = z.infer<typeof PrivateKeyBase16>;
