import { z } from "zod";

export class NilauthUnreachable extends Error {
  public readonly _tag = "NilauthUnreachable";
  constructor(
    public readonly url: string,
    public override readonly cause?: unknown,
  ) {
    super(`Failed to reach Nilauth service at ${url}`);
  }
}

export class InvalidContentType extends Error {
  public readonly _tag = "InvalidContentType";
  constructor(
    public readonly response: globalThis.Response,
    public override readonly cause: Error,
  ) {
    super(
      `Invalid content type: status=${response.status} url=${response.url} cause=${cause.message}`,
    );
  }
}

export class PaymentTxFailed extends Error {
  public readonly _tag = "PaymentTxFailed";
  constructor(public override readonly cause: unknown) {
    super("Payment transaction failed.");
  }
}

export const NilauthErrorCodeSchema = z.enum([
  "CANNOT_RENEW_YET",
  "HASH_MISMATCH",
  "INSUFFICIENT_PAYMENT",
  "INTERNAL",
  "INVALID_PUBLIC_KEY",
  "MALFORMED_PAYLOAD",
  "MALFORMED_TRANSACTION",
  "NOT_SUBSCRIBED",
  "PAYMENT_ALREADY_PROCESSED",
  "TRANSACTION_LOOKUP",
  "TRANSACTION_NOT_COMMITTED",
  "UNKNOWN_PUBLIC_KEY",
]);
export type NilauthErrorCode = z.infer<typeof NilauthErrorCodeSchema>;

export const NilauthErrorResponseBodySchema = z.object({
  message: z.string(),
  error_code: NilauthErrorCodeSchema,
});
export type NilauthErrorResponseBody = z.infer<
  typeof NilauthErrorResponseBodySchema
>;

export class NilauthErrorResponse extends Error {
  public readonly _tag = "NilauthErrorResponse";
  constructor(
    public readonly url: string,
    public readonly code: NilauthErrorCode,
    public override readonly message: string,
    public readonly status: number,
    public override readonly cause?: unknown,
  ) {
    super(`[${code}] ${message} (url=${url}, status=${status})`);
  }
}
