import { Log } from "#/core/logger";
import { Policy } from "#/nuc/policy";
import type { ValidationParameters } from "./types";

export const POLICY_TOO_DEEP = "policy is too deep";
export const POLICY_TOO_WIDE = "policy is too wide";

/**
 * Validate policies properties
 */
export function validatePolicyProperties(
  policy: Policy,
  config: Required<Omit<ValidationParameters, "tokenRequirements">>,
): void {
  if (policy.length > config.maxPolicyWidth) {
    Log.debug(
      { policyLength: policy.length, maxPolicyWidth: config.maxPolicyWidth },
      POLICY_TOO_WIDE,
    );
    throw new Error(POLICY_TOO_WIDE);
  }

  const properties = Policy.getPolicyTreeProperties(policy);
  if (properties.maxWidth > config.maxPolicyWidth) {
    Log.debug(
      { maxWidth: properties.maxWidth, maxPolicyWidth: config.maxPolicyWidth },
      POLICY_TOO_WIDE,
    );
    throw new Error(POLICY_TOO_WIDE);
  }
  if (properties.maxDepth > config.maxPolicyDepth) {
    Log.debug(
      { maxDepth: properties.maxDepth, maxPolicyDepth: config.maxPolicyDepth },
      POLICY_TOO_DEEP,
    );
    throw new Error(POLICY_TOO_DEEP);
  }
}
