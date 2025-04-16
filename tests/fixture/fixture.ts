import { Keypair } from "#/keypair";
import { NilauthClient } from "#/nilauth/client";
import { PayerBuilder } from "#/payer/builder";
import { Env } from "./env";

export type TestFixture = {
  nilauthClient: NilauthClient;
};

export async function buildFixture(privateKey: string): Promise<TestFixture> {
  const keypair = Keypair.from(privateKey);
  const payer = await new PayerBuilder()
    .chainUrl(Env.nilChainUrl)
    .keypair(keypair)
    .build();

  const nilauthClient = await NilauthClient.from({
    keypair,
    payer,
    baseUrl: Env.nilAuthUrl,
  });

  return {
    nilauthClient,
  };
}
