import { Data } from "effect";
import { z } from "zod";

/**
 * Error thrown when a service cannot be contacted.
 * Used when network requests fail to establish a connection to the target.
 *
 * @property url - Target server URL.
 * @property cause - The original error that caused the failure (optional).
 */
export class NilauthUnreachable extends Data.TaggedError("NilauthUnreachable")<{
  url: string;
  cause?: unknown;
}> {
  /**
   * Returns a formatted string for logging.
   */
  toString(): string {
    const causeStr =
      this.cause instanceof Error
        ? this.cause.message
        : this.cause
          ? String(this.cause)
          : "unknown";
    return `${this._tag}: ${this.url}${causeStr ? ` cause=${causeStr}` : ""}`;
  }
}

/**
 * Error thrown when the response content type does not match expectations.
 *
 * @property actual - The actual content type received.
 * @property expected - The expected content type.
 * @property response - The original Response object.
 * @property cause - The underlying error.
 */
export class InvalidContentType extends Data.TaggedError("InvalidContentType")<{
  actual: string | null;
  expected: "application/json" | "plain/text";
  response: globalThis.Response;
  cause: Error;
}> {
  /**
   * Returns a formatted string for logging.
   */
  toString(): string {
    return `${this._tag}: status=${this.response.status} url=${this.response.url} expected=${this.expected} actual=${this.actual} cause=${this.cause.message}`;
  }
}

/**
 * Error thrown when a payment transaction fails.
 *
 * @property cause - The underlying error or reason for the failure.
 */
export class PaymentTxFailed extends Data.TaggedError("PaymentTxFailed")<{
  cause: unknown;
}> {
  /**
   * Returns a formatted string for logging.
   */
  toString(): string {
    const causeStr =
      this.cause instanceof Error
        ? this.cause.message
        : this.cause
          ? String(this.cause)
          : "unknown";
    return `${this._tag}: cause=${causeStr}`;
  }
}

/**
 * Zod schema and type for all known Nilauth error codes returned by the server.
 */
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

/**
 * Zod schema for a structured error response from the Nilauth server.
 *
 * @property message - Human-readable error message.
 * @property code - Machine-readable error code.
 */
export const NilauthErrorResponseSchema = z.object({
  message: z.string(),
  error_code: NilauthErrorCodeSchema,
});

/**
 * Error thrown when the Nilauth server returns a structured error response.
 *
 * @property url - The request URL.
 * @property code - The error code returned by the server.
 * @property message - The error message returned by the server.
 * @property status - The HTTP status code.
 * @property cause - The underlying error or response body (optional).
 */
export class NilauthErrorResponse extends Data.TaggedError(
  "NilauthErrorResponse",
)<{
  url: string;
  code: NilauthErrorCode;
  message: string;
  status: number;
  cause?: unknown;
}> {
  /**
   * Returns a formatted string for logging.
   */
  toString(): string {
    const causeStr =
      this.cause instanceof Error
        ? this.cause.message
        : this.cause
          ? String(this.cause)
          : "";
    return `${this._tag}: [${this.code}] ${this.message} (url=${this.url}, status=${this.status})${causeStr ? ` cause=${causeStr}` : ""}`;
  }
}
