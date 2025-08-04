import _ from "es-toolkit/compat";
import { z } from "zod";
import { Log } from "#/core/logger";
import { applySelector, type Selector } from "#/nuc/selector";

/**
 * Simple type aliases for operators
 */
export type Equals = readonly ["==", Selector | string, unknown];
export type NotEquals = readonly ["!=", Selector | string, unknown];
export type AnyOf = readonly ["anyOf", Selector | string, unknown[]];

/**
 * Union type for all operators
 */
export type Operator = Equals | NotEquals | AnyOf;

/**
 * Logical connectors for combining policies
 */
export type And = readonly ["and", PolicyRule[]];
export type Or = readonly ["or", PolicyRule[]];
export type Not = readonly ["not", PolicyRule];

/**
 * Union type for all connectors
 */
export type Connector = And | Or | Not;

/**
 * A PolicyRule is either an Operator or a Connector
 */
export type PolicyRule = Operator | Connector;

/**
 * A Policy is an array of PolicyRules (with implicit AND)
 */
export type Policy = PolicyRule[];

export namespace Policy {
  /**
   * Runtime validation for a single policy rule.
   */
  export function validateRule(rule: unknown): asserts rule is PolicyRule {
    if (!Array.isArray(rule) || rule.length < 2) {
      throw new Error("Policy rule must be an array with at least 2 elements");
    }

    const [op, ...args] = rule;

    switch (op) {
      case "==":
      case "!=":
        if (args.length !== 2) {
          throw new Error(`Operator ${op} requires exactly 2 arguments`);
        }
        break;
      case "anyOf":
        if (args.length !== 2 || !Array.isArray(args[1])) {
          throw new Error("Operator anyOf requires a selector and an array");
        }
        break;
      case "and":
      case "or":
        if (args.length !== 1 || !Array.isArray(args[0])) {
          throw new Error(`Connector ${op} requires an array of policies`);
        }
        if (args[0].length === 0) {
          throw new Error(`Connector ${op} requires at least one policy`);
        }
        // Recursively validate nested policy rules
        args[0].forEach(validateRule);
        break;
      case "not":
        if (args.length !== 1) {
          throw new Error("Connector not requires exactly one policy rule");
        }
        // Recursively validate nested policy rule
        validateRule(args[0]);
        break;
      default:
        throw new Error(`Unknown policy operator: ${op}`);
    }
  }

  /**
   * Runtime validation for policy structure.
   */
  export function validate(policy: unknown): asserts policy is Policy {
    if (!Array.isArray(policy)) {
      throw new Error("Policy must be an array");
    }

    // Allow empty policies (no rules = no restrictions)
    if (policy.length === 0) {
      return;
    }

    // Validate each rule in the policy
    policy.forEach(validateRule);
  }

  /**
   * Simple schema that uses our validation function
   */
  export const Schema = z.custom<Policy>(
    (val): val is Policy => {
      try {
        validate(val);
        return true;
      } catch {
        return false;
      }
    },
    { message: "Invalid policy structure" },
  );

  /**
   * Evaluates a policy against a record and context
   *
   * @example
   * ```typescript
   * const policy: Policy = [
   *   ["==", ".status", "active"],
   *   ["!=", ".role", "banned"]
   * ];
   * const record = { status: "active", role: "user" };
   * const context = { environment: "production" };
   *
   * Policy.evaluatePolicy(policy, record, context); // true
   * ```
   */
  export function evaluatePolicy(
    policy: Policy,
    record: Record<string, unknown>,
    context: Record<string, unknown>,
  ): boolean {
    Log.debug({ policy, record, context }, "Evaluating policy");

    // A policy is an array of rules with implicit AND
    for (const rule of policy) {
      if (!evaluatePolicyRule(rule, record, context)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Calculates the maximum depth and width of a policy tree
   *
   * @remarks
   * - Depth: The longest path from root to leaf in the policy tree
   * - Width: The maximum number of sibling policies at any level
   *
   * @example
   * ```typescript
   * const policy: Policy = [
   *   ["==", ".status", "active"],
   *   ["or", [
   *     ["==", ".role", "admin"],
   *     ["==", ".role", "moderator"]
   *   ]]
   * ];
   *
   * Policy.getPolicyTreeProperties(policy); // returns { maxDepth: 3, maxWidth: 2 }
   * ```
   */
  export function getPolicyTreeProperties(policy: Policy): {
    maxDepth: number;
    maxWidth: number;
  } {
    Log.debug({ policy }, "Analyzing policy tree properties");

    function analyzeRule(rule: PolicyRule): { depth: number; width: number } {
      // base case
      if (isOperator(rule)) {
        return { depth: 1, width: 1 };
      }

      const [op, childPolicy] = rule;
      if (op === "not") {
        const result = analyzeRule(childPolicy);
        return { depth: result.depth + 1, width: result.width };
      }

      // and/or cases
      const results = childPolicy.map(analyzeRule);
      return {
        depth: 1 + Math.max(...results.map((r) => r.depth), 0),
        width: Math.max(childPolicy.length, ...results.map((r) => r.width)),
      };
    }

    // For a policy (array of rules with implicit AND), analyze as if it were an AND connector
    if (policy.length === 1) {
      const result = analyzeRule(policy[0]);
      Log.info(
        { maxDepth: result.depth, maxWidth: result.width },
        "Policy tree analysis complete",
      );
      return {
        maxDepth: result.depth,
        maxWidth: result.width,
      };
    }

    const results = policy.map(analyzeRule);
    const result = {
      maxDepth: 1 + Math.max(...results.map((r) => r.depth), 0),
      maxWidth: Math.max(policy.length, ...results.map((r) => r.width)),
    };

    Log.info(
      { maxDepth: result.maxDepth, maxWidth: result.maxWidth },
      "Policy tree analysis complete",
    );

    return result;
  }
}

/**
 * Evaluates a single policy rule against a record and context
 */
function evaluatePolicyRule(
  rule: PolicyRule,
  record: Record<string, unknown>,
  context: Record<string, unknown>,
): boolean {
  Log.debug({ rule, record, context }, "Evaluating policy rule");

  if (isOperator(rule)) {
    const [op, selector, value] = rule;
    const selectorValue = typeof selector === "string" ? selector : selector;
    const selectedValue = applySelector(
      selectorValue as Selector,
      record,
      context,
    );

    Log.debug(
      {
        operator: op,
        selector,
        expectedValue: value,
        actualValue: selectedValue,
      },
      "Evaluating operator",
    );

    switch (op) {
      case "==": {
        const result = _.isEqual(selectedValue, value);
        Log.debug(
          {
            selector,
            expectedValue: value,
            actualValue: selectedValue,
            result,
          },
          "Equality check",
        );
        return result;
      }

      case "!=": {
        const result = !_.isEqual(selectedValue, value);
        Log.debug(
          {
            selector,
            expectedValue: value,
            actualValue: selectedValue,
            result,
          },
          "Inequality check",
        );
        return result;
      }

      case "anyOf": {
        const result = value.some((option) => _.isEqual(selectedValue, option));
        Log.debug(
          { selector, actualValue: selectedValue, options: value, result },
          "AnyOf check",
        );
        return result;
      }
    }
  }

  const [op, childPolicy] = rule;
  Log.debug({ connector: op }, "Evaluating connector");

  switch (op) {
    case "and": {
      Log.debug({ totalRules: childPolicy.length }, "Evaluating AND connector");
      for (let i = 0; i < childPolicy.length; i++) {
        const result = evaluatePolicyRule(childPolicy[i], record, context);
        if (!result) {
          Log.debug(
            { failedAt: i, rule: childPolicy[i] },
            "AND connector short-circuited",
          );
          return false;
        }
      }
      Log.debug("AND connector: all rules passed");
      return true;
    }

    case "or": {
      Log.debug({ totalRules: childPolicy.length }, "Evaluating OR connector");
      const result = childPolicy.some((r, i) => {
        const res = evaluatePolicyRule(r, record, context);
        if (res) {
          Log.debug({ passedAt: i, rule: r }, "OR connector short-circuited");
        }
        return res;
      });
      if (!result) {
        Log.debug("OR connector: no rules passed");
      }
      return result;
    }

    case "not": {
      Log.debug("Evaluating NOT connector");
      const innerResult = evaluatePolicyRule(childPolicy, record, context);
      const result = !innerResult;
      Log.debug({ innerResult, result }, "NOT connector result");
      return result;
    }
  }
}

/**
 * Type guard to check if a policy rule is an operator
 *
 * @internal
 */
function isOperator(rule: PolicyRule): rule is Operator {
  return ["==", "!=", "anyOf"].includes(rule[0]);
}
