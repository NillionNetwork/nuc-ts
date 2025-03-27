import { AuthorityService } from "#/authority";
import { Keypair } from "#/keypair";
import { PayerBuilder } from "#/payer/builder";
import type { Payer } from "#/payer/client";
import { Env } from "./env";

export type TestFixture = {
  keypair: Keypair;
  payer: Payer;
  authorityService: AuthorityService;
};

export async function buildFixture(privateKey: string): Promise<TestFixture> {
  const keypair = Keypair.from(privateKey);
  const payer = await new PayerBuilder()
    .chainUrl(Env.nilChainUrl)
    .keypair(keypair)
    .build();
  return {
    keypair,
    payer,
    authorityService: new AuthorityService(Env.nilAuthUrl),
  };
}
