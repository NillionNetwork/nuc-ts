import { describe, it } from "vitest";
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
    expected: { type: "anyOf", selector: ["foo"], values: [42, "hi"] },
  },
  {
    test: "anyOf2",
    input: ["anyOf", ".foo", [{ foo: 42 }]],
    expected: { type: "anyOf", selector: ["foo"], values: [{ foo: 42 }] },
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
      policies: [
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
      policies: [
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
      policy: { type: "equals", selector: ["foo"], value: 42 },
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
      policies: [
        { type: "equals", selector: ["foo"], value: 42 },
        {
          type: "and",
          policies: [
            { type: "notEquals", selector: ["bar"], value: 1337 },
            {
              type: "not",
              policy: { type: "equals", selector: ["tar"], value: true },
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
