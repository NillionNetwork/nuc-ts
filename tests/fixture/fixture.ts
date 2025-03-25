import { AuthorityService } from "#/authority";
import { Keypair } from "#/keypair";
import { PayerBuilder } from "#/payer/builder";
import type { Payer } from "#/payer/client";
import { AuthorityServer } from "./authority-server";
import { Env } from "./env";

export type TestFixture = {
  keypair: Keypair;
  payer: Payer;
  authorityServer: AuthorityServer;
  authorityService: AuthorityService;
};

export async function buildFixture(privateKey: string): Promise<TestFixture> {
  const keypair = Keypair.from(privateKey);
  const payer = await new PayerBuilder()
    .chainUrl(Env.nilChainUrl)
    .keypair(keypair)
    .build();

  const authorityServer = new AuthorityServer(Keypair.generate());
  authorityServer.init();

  return {
    keypair,
    payer,
    authorityServer,
    authorityService: new AuthorityService(authorityServer.baseUrl),
  };
}
