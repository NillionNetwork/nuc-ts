import { Effect as E, Schedule, pipe } from "effect";
import z from "zod";
import { log } from "#/logger";

export type NilauthRequest = {
  url: string;
  timeout: number;
  init?: RequestInit;
  retryDelays?: number[];
  retryWhile?: (error: NilauthError) => boolean;
};

const NilauthResponseSchema = z.union([
  z.string(),
  z.record(z.unknown()),
  z.null(),
]);
export type NilauthResponse = z.infer<typeof NilauthResponseSchema>;

export class NilauthError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(`${code}: ${message}`);
  }
}
const NilauthErrorSchema = z
  .object({
    error_code: z.string(),
    message: z.string(),
  })
  .transform(
    ({ error_code, message }) => new NilauthError(error_code, message),
  );

export async function sendRequest(
  request: NilauthRequest,
): Promise<NilauthResponse> {
  const {
    url,
    timeout,
    init,
    retryDelays = [],
    retryWhile = (_) => false,
  } = request;
  const maxRetries = retryDelays.length;
  return pipe(
    E.retry(
      pipe(
        E.tryPromise(() => fetchWithTimeout(url, timeout, init)),
        E.andThen((response) => parseNilauthResponse(response)),
      ),
      pipe(
        Schedule.recurs(maxRetries),
        Schedule.delayed(() => retryDelays.shift() ?? 0),
        Schedule.whileInput((error) => {
          if (error instanceof NilauthError && retryWhile(error)) {
            log(`retrying: ${error}`);
            return true;
          }
          if (error instanceof Error && error.cause === "timeout") {
            log(`retrying: ${error.cause}`);
            return true;
          }
          return false;
        }),
      ),
    ),
    E.runPromise,
  );
}

async function fetchWithTimeout(
  url: string,
  timeout: number,
  init?: RequestInit,
): Promise<Response> {
  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject("timeout"), timeout),
  );
  return (await Promise.race([fetch(url, init), timeoutPromise])) as Response;
}

function parseNilauthResponse(
  response: Response,
): E.Effect<NilauthResponse, Error> {
  const contentType = response.headers.get("content-type");
  if (!contentType) return E.fail(new Error("content-type not found"));
  if (contentType.includes("text/plain")) {
    return pipe(
      E.tryPromise(() => response.text()),
      E.flatMap((body) => E.try(() => NilauthResponseSchema.parse(body))),
    );
  }
  if (contentType === "application/json") {
    if (!response.ok)
      return pipe(
        E.tryPromise(() => response.json()),
        E.flatMap((body) => E.try(() => NilauthErrorSchema.parse(body))),
        E.flatMap((body) => E.fail(body)),
      );
    return pipe(
      E.tryPromise(() => response.json()),
      E.flatMap((body) => E.try(() => NilauthResponseSchema.parse(body))),
    );
  }
  return E.fail(new Error("unsupported content-type"));
}
