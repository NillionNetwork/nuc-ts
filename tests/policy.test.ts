import { describe, it } from "vitest";
import { evaluatePolicy } from "#/policy";
import { OperatorSchema, type Policy, PolicySchema } from "#/types";

describe.each([
  {
    test: "eq",
    input: ["==", ".foo", { ".bar": 42 }],
    expected: { type: "equals", selector: ["foo"], value: { ".bar": 42 } },
  },
  {
    test: "ne",
    input: ["!=", ".foo", { ".bar": 42 }],
    expected: { type: "notEquals", selector: ["foo"], value: { ".bar": 42 } },
  },
  {
    test: "anyOf1",
    input: ["anyOf", ".foo", [42, "hi"]],
    expected: { type: "anyOf", selector: ["foo"], options: [42, "hi"] },
  },
  {
    test: "anyOf2",
    input: ["anyOf", ".foo", [{ foo: 42 }]],
    expected: { type: "anyOf", selector: ["foo"], options: [{ foo: 42 }] },
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
    expected: {
      type: "and",
      conditions: [
        { type: "equals", selector: ["foo"], value: 42 },
        { type: "notEquals", selector: ["bar"], value: false },
      ],
    },
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
    expected: {
      type: "or",
      conditions: [
        { type: "equals", selector: ["foo"], value: 42 },
        { type: "notEquals", selector: ["bar"], value: false },
      ],
    },
  },
  {
    test: "not",
    input: ["not", ["==", ".foo", 42]],
    expected: {
      type: "not",
      condition: { type: "equals", selector: ["foo"], value: 42 },
    },
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
    expected: {
      type: "or",
      conditions: [
        { type: "equals", selector: ["foo"], value: 42 },
        {
          type: "and",
          conditions: [
            { type: "notEquals", selector: ["bar"], value: 1337 },
            {
              type: "not",
              condition: { type: "equals", selector: ["tar"], value: true },
            },
          ],
        },
      ],
    },
  },
])("valid policy", ({ test, input, expected }) => {
  it(`${test}`, ({ expect }) => {
    const result: Policy = PolicySchema.parse(input);
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
    expect(() => OperatorSchema.parse(input)).toThrowError();
  });
});

describe.each([
  {
    test: "eq value",
    policy: { type: "equals", selector: ["name", "first"], value: "bob" },
  },
  {
    test: "ne",
    policy: { type: "notEquals", selector: ["name", "first"], value: "john" },
  },
  {
    test: "eq object",
    policy: {
      type: "equals",
      selector: ["name"],
      value: { first: "bob", last: "smith" },
    },
  },
  {
    test: "eq root",
    policy: {
      type: "equals",
      selector: [],
      value: { name: { first: "bob", last: "smith" }, age: 42 },
    },
  },
  {
    test: "notEq",
    policy: { type: "notEquals", selector: ["age"], value: 150 },
  },
  {
    test: "anyOf",
    policy: {
      type: "anyOf",
      selector: ["name", ["first"]],
      options: ["john", "bob"],
    },
  },
  {
    test: "and",
    policy: {
      type: "and",
      conditions: [
        { type: "equals", selector: ["age"], value: 42 },
        { type: "equals", selector: ["name", "first"], value: "bob" },
      ],
    },
  },
  {
    test: "or short circuit",
    policy: {
      type: "or",
      conditions: [
        { type: "equals", selector: ["age"], value: 42 },
        { type: "equals", selector: ["age"], value: 100 },
      ],
    },
  },
  {
    test: "or long circuit",
    policy: {
      type: "or",
      conditions: [
        { type: "equals", selector: ["age"], value: 100 },
        { type: "equals", selector: ["age"], value: 42 },
      ],
    },
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
    const result = evaluatePolicy(policy, value);
    expect(result).toBe(true);
  });
});

describe.each([
  {
    test: "eq value",
    policy: { type: "equals", selector: ["name", "first"], value: "john" },
  },
  {
    test: "ne",
    policy: { type: "notEquals", selector: ["name", "first"], value: "bob" },
  },
  {
    test: "eq object",
    policy: {
      type: "equals",
      selector: ["name"],
      value: { first: "john", last: "smith" },
    },
  },
  {
    test: "eq root",
    policy: {
      type: "equals",
      selector: [],
      value: { name: { first: "bob", last: "smith" }, age: 100 },
    },
  },
  {
    test: "notEq",
    policy: { type: "notEquals", selector: ["age"], value: 42 },
  },
  {
    test: "anyOf",
    policy: {
      type: "anyOf",
      selector: ["name", ["first"]],
      options: ["john", "jack"],
    },
  },
  {
    test: "and1",
    policy: {
      type: "and",
      conditions: [
        { type: "equals", selector: ["age"], value: 150 },
        { type: "equals", selector: ["name", "first"], value: "bob" },
      ],
    },
  },
  {
    test: "and2",
    policy: {
      type: "and",
      conditions: [
        { type: "equals", selector: ["age"], value: 42 },
        { type: "equals", selector: ["name", "first"], value: "john" },
      ],
    },
  },
  { test: "empty and", policy: { type: "and", conditions: [] } },
  {
    test: "or",
    policy: {
      type: "or",
      conditions: [
        { type: "equals", selector: ["age"], value: 101 },
        { type: "equals", selector: ["age"], value: 100 },
      ],
    },
  },
  { test: "or empty", policy: { type: "or", conditions: [] } },
])("evaluation does not matches", ({ test, policy }) => {
  it(`${test}`, ({ expect }) => {
    const value = {
      name: {
        first: "bob",
        last: "smith",
      },
      age: 42,
    };
    const result = evaluatePolicy(policy, value);
    expect(result).toBe(false);
  });
});
