import { describe, it } from "vitest";
import { OperatorSchema, PolicySchema } from "#/types";

describe.each([
  { test: "eq", input: ["==", ".foo", { ".bar": 42 }] },
  { test: "ne", input: ["!=", ".foo", { ".bar": 42 }] },
  { test: "anyOf1", input: ["anyOf", ".foo", [42, "hi"]] },
  { test: "anyOf2", input: ["anyOf", ".foo", [{ foo: 42 }]] },
  {
    test: "and",
    input: [
      "and",
      [
        ["==", ".foo", 42],
        ["!=", ".bar", false],
      ],
    ],
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
  },
  { test: "not", input: ["not", ["==", ".foo", 42]] },
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
  },
])("valid policy", ({ test, input }) => {
  it(`${test}`, ({ expect }) => {
    const result = PolicySchema.parse(input);
    expect(result).toBeDefined;
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
