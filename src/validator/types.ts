/**
 * Token requirement types
 */
export type TokenRequirement = { type: "invocation"; audience: string } | { type: "delegation"; audience: string };

/**
 * Validation parameters configuration
 */
export type ValidationParameters = {
  maxChainLength?: number;
  maxPolicyWidth?: number;
  maxPolicyDepth?: number;
  tokenRequirements?: TokenRequirement;
};

/**
 * Validation options configuration
 */
export type ValidationOptions = {
  rootIssuers: string[];
  params?: ValidationParameters;
  context?: Record<string, unknown>;
  timeProvider?: () => number;
};
