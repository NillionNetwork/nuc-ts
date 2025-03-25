import { AuthorityService } from "#/authority";
import { PayerBuilder } from "#/payer/builder";
import type { Payer } from "#/payer/client";
import { Wallet } from "#/payer/wallet";
import { AuthorityServer } from "./authority-server";
import { Env } from "./env";

export type TestFixture = {
  signer: Wallet;
  payer: Payer;
  authorityServer: AuthorityServer;
  authorityService: AuthorityService;
};

export async function buildFixture(privateKey: string): Promise<TestFixture> {
  const signer = new Wallet(privateKey);
  const payer = await new PayerBuilder()
    .chainUrl(Env.nilChainUrl)
    .signer(await signer.signer())
    .build();
  const authorityServer = new AuthorityServer(Wallet.generate());
  authorityServer.init();
  return {
    signer,
    payer,
    authorityServer,
    authorityService: new AuthorityService(authorityServer.baseUrl),
  };
}
