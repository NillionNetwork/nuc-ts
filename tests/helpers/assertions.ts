import * as didKey from "#/core/did/key";
import type { Envelope } from "#/nuc/envelope";
import { type ValidationParameters, Validator } from "#/validator/validator";
import { secp256k1 } from "@noble/curves/secp256k1.js";

export const ROOT_KEYS = [secp256k1.utils.randomSecretKey()];
export const ROOT_DIDS: string[] = ROOT_KEYS.map((privKey) =>
  didKey.fromPublicKeyBytes(secp256k1.getPublicKey(privKey)),
);

export type AsserterConfiguration = {
  parameters?: ValidationParameters;
  rootDids?: string[];
  context?: Record<string, unknown>;
  currentTime?: number;
};

export async function assertSuccess(envelope: Envelope, config: AsserterConfiguration = {}): Promise<void> {
  const timeProvider =
    config.currentTime === undefined
      ? undefined
      : (): number => {
          if (config.currentTime === undefined) {
            throw new Error("currentTime unexpectedly undefined");
          }
          return config.currentTime;
        };

  await Validator.validate(envelope, {
    rootIssuers: config.rootDids ?? ROOT_DIDS,
    params: config.parameters,
    context: config.context,
    timeProvider,
  });
}

export async function assertFailure(
  envelope: Envelope,
  expectedMessage: string,
  config: AsserterConfiguration = {},
): Promise<void> {
  const timeProvider =
    config.currentTime !== undefined
      ? (): number => {
          if (config.currentTime === undefined) {
            throw new Error("currentTime unexpectedly undefined");
          }
          return config.currentTime;
        }
      : undefined;

  try {
    await Validator.validate(envelope, {
      rootIssuers: config.rootDids ?? ROOT_DIDS,
      params: config.parameters,
      context: config.context,
      timeProvider,
    });
  } catch (e) {
    if (e instanceof Error) {
      if (e.message === expectedMessage) {
        // Test passes
        return;
      }
      throw new Error(`Validation failed with unexpected message: expected '${expectedMessage}', got '${e.message}'`);
    }
    // Re-throw if it's not a standard Error
    throw e;
  }
  throw new Error(`Validation succeeded but was expected to fail with: ${expectedMessage}`);
}
