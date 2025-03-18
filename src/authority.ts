import { randomBytes } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { Effect as E, pipe } from "effect";
import { Temporal } from "temporal-polyfill";
import z from "zod";
import { NucTokenEnvelopeSchema } from "#/envelope";

export const AuthorityServiceAboutSchema = z
  .object({
    public_key: z.string(),
  })
  .transform((d) => {
    return { publicKey: d.public_key };
  });
export type AuthorityServiceAbout = z.infer<typeof AuthorityServiceAboutSchema>;

export const CreateTokenResponseSchema = z.object({
  token: NucTokenEnvelopeSchema,
});
export type CreateTokenResponse = z.infer<typeof CreateTokenResponseSchema>;

export class AuthorityService {
  constructor(
    private baseUrl: string,
    private timeout = 10000,
  ) {}

  async about(): Promise<AuthorityServiceAbout> {
    return pipe(
      E.tryPromise(() =>
        fetchWithTimeout(`${this.baseUrl}/about`, this.timeout),
      ),
      E.flatMap((data) => E.try(() => AuthorityServiceAboutSchema.parse(data))),
      E.catchAll((e) => E.fail(e.cause)),
      E.runPromise,
    );
  }

  async requestToken(key: Uint8Array): Promise<CreateTokenResponse> {
    const aboutResponse = await this.about();

    const payload = JSON.stringify({
      nonce: randomBytes(16).toString("hex"),
      target_public_key: aboutResponse.public_key,
      expires_at: Temporal.Now.instant().epochSeconds + 60,
    });

    const signature = secp256k1.sign(
      new Uint8Array(Buffer.from(payload)),
      key,
      { prehash: true },
    );
    const request = {
      public_key: Buffer.from(secp256k1.getPublicKey(key)).toString("hex"),
      signature: signature.toCompactHex(),
      payload: Buffer.from(payload).toString("hex"),
    };
    return pipe(
      E.tryPromise(() =>
        fetchWithTimeout(`${this.baseUrl}/api/v1/nucs/create`, this.timeout, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
        }),
      ),
      E.flatMap((response) =>
        E.try(() => CreateTokenResponseSchema.parse(response)),
      ),
      E.catchAll((e) => E.fail(e.cause)),
      E.runPromise,
    );
  }
}

async function fetchWithTimeout(
  url: string,
  timeout: number,
  init?: RequestInit,
): Promise<unknown> {
  const fetchPromise = pipe(
    E.tryPromise(() => fetch(url, init)),
    E.andThen((response) => response.json()),
    E.runPromise,
  );

  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("timeout")), timeout),
  );

  return Promise.race([fetchPromise, timeoutPromise]);
}
