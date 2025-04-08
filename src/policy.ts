import equal from "fast-deep-equal/es6";
import { z } from "zod";
import { type Selector, SelectorSchema } from "#/selector";

/**
 * A policy that restricts how a NUC can be used.
 */
export interface Policy {
  /**
   * Checks whether this policy matches a value.
   * @param record Value against the policy is matched.
   */
  evaluate(record: Record<string, unknown>): boolean;

  /**
   *  Serialize the policy into an array of anything.
   */
  serialize(): Array<unknown>;

  /**
   * Serialize the policy into a string.
   */
  toString(): string;
}

/**
 * A policy that applies a selector on the NUC token and applies an operator to it.
 */
export interface OperatorPolicy extends Policy {}

export const EqualsSchema = z
  .tuple([z.literal("=="), SelectorSchema, z.unknown()])
  .transform((operator) => new Equals(operator[1], operator[2]));

/**
 * An operator that checks for equality.
 */
export class Equals implements OperatorPolicy {
  constructor(
    private readonly selector: Selector,
    private readonly value: unknown,
  ) {}

  evaluate(record: Record<string, unknown>): boolean {
    return equal(this.selector.apply(record), this.value);
  }

  serialize(): Array<unknown> {
    return ["==", this.selector.toString(), this.value];
  }

  toString(): string {
    return JSON.stringify(this.serialize());
  }
}

export const NotEqualsSchema = z
  .tuple([z.literal("!="), SelectorSchema, z.unknown()])
  .transform((operator) => new NotEquals(operator[1], operator[2]));

/**
 * An operator that checks for inequality.
 */
export class NotEquals implements OperatorPolicy {
  constructor(
    private readonly selector: Selector,
    private readonly value: unknown,
  ) {}

  evaluate(record: Record<string, unknown>): boolean {
    return !equal(this.selector.apply(record), this.value);
  }

  serialize(): Array<unknown> {
    return ["!=", this.selector.toString(), this.value];
  }

  toString(): string {
    return JSON.stringify(this.serialize());
  }
}

export const AnyOfSchema = z
  .tuple([z.literal("anyOf"), SelectorSchema, z.array(z.unknown())])
  .transform((operator) => new AnyOf(operator[1], operator[2]));

/**
 * An operator that checks that a value is within a list of values.
 */
export class AnyOf implements OperatorPolicy {
  constructor(
    private readonly selector: Selector,
    public readonly options: Array<unknown>,
  ) {}

  evaluate(record: Record<string, unknown>): boolean {
    const value = this.selector.apply(record);
    return Array.from(this.options).some((option) => equal(value, option));
  }

  serialize(): Array<unknown> {
    return ["anyOf", this.selector.toString(), this.options];
  }

  toString(): string {
    return JSON.stringify(this.serialize());
  }
}

export const OperatorSchema = z.union([
  EqualsSchema,
  NotEqualsSchema,
  AnyOfSchema,
]);

/**
 * Represents a connector of policies.
 */
export interface ConnectorPolicy extends Policy {}

export const AndSchema = z
  .lazy(() => z.tuple([z.literal("and"), z.array(PolicySchema)]))
  .transform(
    (connector) => new And(connector[1].map((policy) => policy as Policy)),
  );

/**
 * A connector that checks that a sequence of policies is valid.
 */
export class And implements ConnectorPolicy {
  constructor(public readonly conditions: Array<Policy>) {}

  evaluate(record: Record<string, unknown>): boolean {
    const conditions = this.conditions;
    return (
      conditions &&
      conditions.length > 0 &&
      conditions.every((condition) => condition.evaluate(record))
    );
  }

  serialize(): Array<unknown> {
    return [
      "and",
      ...this.conditions.map((condition) => condition.serialize()),
    ];
  }

  toString(): string {
    return JSON.stringify(this.serialize());
  }
}

export const OrSchema = z
  .lazy(() => z.tuple([z.literal("or"), z.array(PolicySchema)]))
  .transform(
    (connector) => new Or(connector[1].map((policy) => policy as Policy)),
  );

/**
 * A connector that checks that at least policy in a sequence is valid.
 */
export class Or implements ConnectorPolicy {
  constructor(public readonly conditions: Array<Policy>) {}

  evaluate(record: Record<string, unknown>): boolean {
    return this.conditions.some((condition) => condition.evaluate(record));
  }

  serialize(): Array<unknown> {
    return ["or", ...this.conditions.map((condition) => condition.serialize())];
  }

  toString(): string {
    return JSON.stringify(this.serialize());
  }
}

export const NotSchema = z
  .lazy(() => z.tuple([z.literal("not"), PolicySchema]))
  .transform((connector) => new Not(connector[1] as Policy));

/**
 * A connector that checks that at a policy is not valid.
 */
export class Not implements ConnectorPolicy {
  constructor(public readonly condition: Policy) {}

  evaluate(record: Record<string, unknown>): boolean {
    return !this.condition.evaluate(record);
  }

  serialize(): Array<unknown> {
    return ["not", this.condition.serialize()];
  }

  toString(): string {
    return JSON.stringify(this.serialize());
  }
}

export const ConnectorSchema = z.lazy(() =>
  z.union([AndSchema, OrSchema, NotSchema]),
);

export const PolicySchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([ConnectorSchema, OperatorSchema]),
);
