import { Log } from "#/core/logger";
import type { Payload } from "#/nuc/payload";

export const NOT_BEFORE_NOT_MET = "`not before` date not met";
export const TOKEN_EXPIRED = "token is expired";

/**
 * Validate temporal properties of a token
 */
export function validateTemporalProperties(
  payload: Payload,
  currentTime: number,
): void {
  // Convert currentTime from milliseconds to seconds for comparison
  const currentTimeInSeconds = Math.floor(currentTime / 1000);

  if (payload.exp && payload.exp <= currentTimeInSeconds) {
    Log.debug(
      { expiredAt: payload.exp, now: currentTimeInSeconds },
      TOKEN_EXPIRED,
    );
    throw new Error(TOKEN_EXPIRED);
  }

  if (payload.nbf && payload.nbf > currentTimeInSeconds) {
    Log.debug(
      { notBefore: payload.nbf, now: currentTimeInSeconds },
      NOT_BEFORE_NOT_MET,
    );
    throw new Error(NOT_BEFORE_NOT_MET);
  }
}
