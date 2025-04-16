import { Effect as E, pipe } from "effect";
import {
  NilauthErrorCodeSchema,
  NilauthErrorResponse,
  NilauthErrorResponseSchema,
  NilauthUnreachable,
} from "#/errors";
import { assertType, extractResponseJson, parseWithZodSchema } from "#/utils";

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export type FetchError = NilauthUnreachable | NilauthErrorResponse;

export type RequestOptions = {
  url: string;
  method: "POST" | "GET";
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
};

/**
 * Performs a fetch request with a timeout and effectful error handling.
 *
 * - If the request times out, the Effect fails with `NilauthUnreachable`.
 * - If a network or other fetch-related error occurs, the Effect fails with `NilauthUnreachable`.
 * - If the HTTP response is not OK (non-2xx), attempts to parse the error response body as a known
 *   Nilauth error and fail with a typed `NilauthErrorResponse`. If parsing fails, fails with a generic
 *   `NilauthErrorResponse` containing the cause and HTTP status.
 *
 * @param request - The request parameters, including URL, HTTP method, (optional) headers, and body.
 * @returns An Effect that resolves to a Response on success or fails with a `FetchError`.
 */
export function fetchWithTimeout(
  request: RequestOptions,
): E.Effect<Response, FetchError> {
  const { url, method, headers, body } = request;

  return pipe(
    // Attempt the fetch as a Promise, handling abort and network errors.
    E.tryPromise({
      try: () => {
        const controller = new AbortController();
        // Set up a timeout to abort the request if it takes too long.
        const timeoutId = setTimeout(
          () => controller.abort(),
          DEFAULT_REQUEST_TIMEOUT_MS,
        );

        try {
          return fetch(url, {
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined,
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeoutId); // clear the timeout.
        }
      },
      // Map any thrown error to a NilauthUnreachable, distinguishing timeout from other errors.
      catch: (error) => {
        const cause =
          error instanceof DOMException && error.name === "AbortError"
            ? "timed-out"
            : error;

        return new NilauthUnreachable({
          url,
          cause,
        });
      },
    }),
    // Handle the HTTP response.
    E.flatMap((response): E.Effect<Response, FetchError> => {
      if (response.ok) {
        // If the response is OK (2xx), succeed with the Response object.
        return E.succeed(response);
      }

      // For non-2xx responses, attempt to parse the error response body as a known Nilauth error.
      return pipe(
        E.succeed(response),
        extractResponseJson(),
        parseWithZodSchema(NilauthErrorResponseSchema),
        assertType<NilauthErrorResponse>(),

        // If parsing fails, map the error to a generic NilauthErrorResponse with details.
        E.mapError(
          (cause) =>
            new NilauthErrorResponse({
              url,
              code: NilauthErrorCodeSchema.enum.INTERNAL,
              message: "Failed to parse non 200 status code",
              status: response.status,
              cause,
            }),
        ),

        // If we get to this point the response represents a failure, even if it was successfully
        // parsed, so we need to switch onto the failure track
        E.flatMap(E.fail),
      );
    }),
  );
}
