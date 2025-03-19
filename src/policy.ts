import equal from "fast-deep-equal/es6";
import type {
  And,
  AnyOf,
  Connector,
  Equals,
  Not,
  NotEquals,
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
  const value = operator.selector.apply(record);
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

export function serializeOperator(operator: Operator): Array<unknown> {
  const selector = operator.selector.toString();
  switch (operator.type) {
    case "equals":
      return ["==", selector, (operator as Equals).value];
    case "notEquals":
      return ["!=", selector, (operator as NotEquals).value];
    case "anyOf":
      return ["anyOf", selector, (operator as AnyOf).options];
    default:
      throw new Error(`Unexpected policy "${operator.type}"`);
  }
}

export function serializePolicy(policy: Policy): Array<unknown> {
  const policyType = (policy as Connector | Operator).type;
  switch (policyType) {
    case "equals":
    case "notEquals":
    case "anyOf":
      return serializeOperator(policy as Operator);
    case "and": {
      const conditions = (policy as And).conditions;
      return [
        "and",
        ...conditions.map((condition) => serializePolicy(condition)),
      ];
    }
    case "or": {
      const conditions = (policy as Or).conditions;
      return [
        "or",
        ...conditions.map((condition) => serializePolicy(condition)),
      ];
    }
    case "not": {
      const condition = (policy as Not).condition;
      return ["not", serializePolicy(condition)];
    }
    default:
      throw new Error(`Unexpected policy "${policyType}"`);
  }
}
