import { describe, it } from "vitest";
import {
  And,
  AnyOf,
  Equals,
  Not,
  NotEquals,
  Or,
  type Policy,
  PolicySchema,
} from "#/policy";
import { SelectorSchema } from "#/selector";

describe.each([
  {
    test: "eq",
    input: ["==", ".foo", { ".bar": 42 }],
    expected: new Equals(SelectorSchema.parse(".foo"), { ".bar": 42 }),
  },
  {
    test: "ne",
    input: ["!=", ".foo", { ".bar": 42 }],
    expected: new NotEquals(SelectorSchema.parse(".foo"), { ".bar": 42 }),
  },
  {
    test: "anyOf1",
    input: ["anyOf", ".foo", [42, "hi"]],
    expected: new AnyOf(SelectorSchema.parse(".foo"), [42, "hi"]),
  },
  {
    test: "anyOf2",
    input: ["anyOf", ".foo", [{ foo: 42 }]],
    expected: new AnyOf(SelectorSchema.parse(".foo"), [{ foo: 42 }]),
  },
  {
    test: "and",
    input: [
      "and",
      [
        ["==", ".foo", 42],
        ["!=", ".bar", false],
      ],
    ],
    expected: new And([
      new Equals(SelectorSchema.parse(".foo"), 42),
      new NotEquals(SelectorSchema.parse(".bar"), false),
    ]),
  },
  {
    test: "or",
    input: [
      "or",
      [
        ["==", ".foo", 42],
        ["!=", ".bar", false],
      ],
    ],
    expected: new Or([
      new Equals(SelectorSchema.parse(".foo"), 42),
      new NotEquals(SelectorSchema.parse(".bar"), false),
    ]),
  },
  {
    test: "not",
    input: ["not", ["==", ".foo", 42]],
    expected: new Not(new Equals(SelectorSchema.parse(".foo"), 42)),
  },
  {
    test: "nested",
    input: [
      "or",
      [
        ["==", ".foo", 42],
        [
          "and",
          [
            ["!=", ".bar", 1337],
            ["not", ["==", ".tar", true]],
          ],
        ],
      ],
    ],
    expected: new Or([
      new Equals(SelectorSchema.parse(".foo"), 42),
      new And([
        new NotEquals(SelectorSchema.parse(".bar"), 1337),
        new Not(new Equals(SelectorSchema.parse(".tar"), true)),
      ]),
    ]),
  },
])("valid policy", ({ test, input, expected }) => {
  it(`${test}`, ({ expect }) => {
    const result = PolicySchema.parse(input) as Policy;
    expect(result).toEqual(expected);
  });
});

describe.each([
  { test: "empty", input: [] },
  { test: "only_op", input: ["=="] },
  { test: "invalid_op", input: ["hi", ".foo", []] },
  { test: "no_value1", input: ["==", ".foo"] },
  { test: "no_value2", input: ["!=", ".foo"] },
  { test: "no_value3", input: ["anyOf", ".foo"] },
  { test: "anyof_no_vec", input: ["anyOf", ".foo", 42] },
  { test: "and_no_vec", input: ["and"] },
  { test: "or_no_vec", input: ["or"] },
  { test: "not_no_policy", input: ["not"] },
  { test: "and_bogus_vec", input: ["and", ["hi"]] },
  { test: "and_bogus_policy", input: ["and", [["hi"]]] },
  { test: "not_bogus_policy", input: ["not", "hi"] },
])("invalid policy", ({ test, input }) => {
  it(`${test}`, ({ expect }) => {
    expect(() => PolicySchema.parse(input)).toThrowError();
  });
});

describe.each([
  {
    test: "eq value",
    policy: new Equals(SelectorSchema.parse(".name.first"), "bob"),
  },
  {
    test: "ne",
    policy: new NotEquals(SelectorSchema.parse(".name.first"), "john"),
  },
  {
    test: "eq object",
    policy: new Equals(SelectorSchema.parse(".name"), {
      first: "bob",
      last: "smith",
    }),
  },
  {
    test: "eq value context",
    policy: new Equals(SelectorSchema.parse("$.req.foo"), 42),
  },
  {
    test: "ne context",
    policy: new NotEquals(SelectorSchema.parse("$.other"), 1335),
  },
  {
    test: "eq root",
    policy: new Equals(SelectorSchema.parse("."), {
      name: { first: "bob", last: "smith" },
      age: 42,
    }),
  },
  {
    test: "notEq",
    policy: new NotEquals(SelectorSchema.parse(".age"), 150),
  },
  {
    test: "anyOf",
    policy: new AnyOf(SelectorSchema.parse(".name.first"), ["john", "bob"]),
  },
  {
    test: "and",
    policy: new And([
      new Equals(SelectorSchema.parse(".age"), 42),
      new Equals(SelectorSchema.parse(".name.first"), "bob"),
    ]),
  },
  {
    test: "or short circuit",
    policy: new Or([
      new Equals(SelectorSchema.parse(".age"), 42),
      new Equals(SelectorSchema.parse(".age"), 100),
    ]),
  },
  {
    test: "or long circuit",
    policy: new Or([
      new Equals(SelectorSchema.parse(".age"), 100),
      new Equals(SelectorSchema.parse(".age"), 42),
    ]),
  },
])("evaluation matches", ({ test, policy }) => {
  it(`${test}`, ({ expect }) => {
    const value = {
      name: {
        first: "bob",
        last: "smith",
      },
      age: 42,
    };
    const context = { req: { foo: 42, bar: "zar" }, other: 1337 };
    const result = policy.evaluate(value, context);
    expect(result).toBe(true);
  });
});

describe.each([
  {
    test: "eq value",
    policy: new Equals(SelectorSchema.parse(".name.first"), "john"),
  },
  {
    test: "ne",
    policy: new NotEquals(SelectorSchema.parse(".name.first"), "bob"),
  },
  {
    test: "eq object",
    policy: new Equals(SelectorSchema.parse(".name"), {
      first: "john",
      last: "smith",
    }),
  },
  {
    test: "eq value context",
    policy: new Equals(SelectorSchema.parse("$.req.foo"), 43),
  },
  {
    test: "ne context",
    policy: new NotEquals(SelectorSchema.parse("$.other"), 1337),
  },
  {
    test: "eq root",
    policy: new Equals(SelectorSchema.parse("."), {
      name: { first: "bob", last: "smith" },
      age: 100,
    }),
  },
  {
    test: "notEq",
    policy: new NotEquals(SelectorSchema.parse(".age"), 42),
  },
  {
    test: "anyOf",
    policy: new AnyOf(SelectorSchema.parse(".name.first"), ["john", "jack"]),
  },
  {
    test: "and1",
    policy: new And([
      new Equals(SelectorSchema.parse(".age"), 150),
      new Equals(SelectorSchema.parse(".name.first"), "bob"),
    ]),
  },
  {
    test: "and2",
    policy: new And([
      new Equals(SelectorSchema.parse(".age"), 42),
      new Equals(SelectorSchema.parse(".name.first"), "john"),
    ]),
  },
  { test: "empty and", policy: new And([]) },
  {
    test: "or",
    policy: new Or([
      new Equals(SelectorSchema.parse(".age"), 101),
      new Equals(SelectorSchema.parse(".age"), 100),
    ]),
  },
  { test: "or empty", policy: new Or([]) },
])("evaluation does not matches", ({ test, policy }) => {
  it(`${test}`, ({ expect }) => {
    const value = {
      name: {
        first: "bob",
        last: "smith",
      },
      age: 42,
    };
    const context = { req: { foo: 42, bar: "zar" }, other: 1337 };
    const result = policy.evaluate(value, context);
    expect(result).toBe(false);
  });
});
