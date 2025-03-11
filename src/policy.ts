import equal from "fast-deep-equal/es6";
import { applySelector } from "#/selector";
import type {
  And,
  AnyOf,
  Connector,
  Equals,
  Not,
  Operator,
  Or,
  Policy,
} from "#/types";

export function evaluatePolicy(
  policy: Policy,
  record: Record<string, unknown>,
): boolean {
  const policyType = (policy as Connector | Operator).type;
  switch (policyType) {
    case "equals":
    case "notEquals":
    case "anyOf":
      return evaluateOperator(policy as Operator, record);
    case "and":
    case "or":
    case "not":
      return evaluateConnector(policy as Connector, record);
    default:
      throw new Error(`Unexpected policy "${policyType}"`);
  }
}

function evaluateOperator(
  operator: Operator,
  record: Record<string, unknown>,
): boolean {
  const value = applySelector(operator.selector, record);
  switch (operator.type) {
    case "equals":
      return equal(value, (operator as Equals).value);
    case "notEquals":
      return !equal(value, (operator as Equals).value);
    case "anyOf":
      return Array.from((operator as AnyOf).options).some((option) =>
        equal(value, option),
      );
    default:
      throw new Error(`Unexpected operator "${operator.type}"`);
  }
}

function evaluateConnector(
  connector: Connector,
  record: Record<string, unknown>,
): boolean {
  switch (connector.type) {
    case "and": {
      const conditions = (connector as And).conditions;
      return (
        conditions &&
        conditions.length > 0 &&
        conditions.every((condition) => evaluatePolicy(condition, record))
      );
    }
    case "or":
      return (connector as Or).conditions.some((condition) =>
        evaluatePolicy(condition, record),
      );
    case "not":
      return !evaluatePolicy((connector as Not).condition, record);
    default:
      throw new Error(`Unexpected connector "${connector.type}"`);
  }
}
