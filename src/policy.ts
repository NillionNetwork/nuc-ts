import equal from "fast-deep-equal/es6";
import { z } from "zod";
import { type Selector, SelectorSchema } from "#/selector";

export interface Policy {
  evaluate(record: Record<string, unknown>): boolean;
  serialize(): Array<unknown>;
  toString(): string;
}

export interface Operator extends Policy {}

export const EqualsSchema = z
  .tuple([z.literal("=="), SelectorSchema, z.unknown()])
  .transform((operator) => new Equals(operator[1], operator[2]));

export class Equals implements Operator {
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

export class NotEquals implements Operator {
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

export class AnyOf implements Operator {
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

export interface Connector extends Policy {}

export const AndSchema = z
  .lazy(() => z.tuple([z.literal("and"), z.array(PolicySchema)]))
  .transform(
    (connector) => new And(connector[1].map((policy) => policy as Policy)),
  );

export class And implements Connector {
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

export class Or implements Connector {
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

export class Not implements Connector {
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
