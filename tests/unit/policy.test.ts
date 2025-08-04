import { describe, expect, test } from "vitest";
import { Policy } from "#/nuc/policy";

describe("Policy", () => {
  test.each([
    {
      case: "eq",
      input: [["==", ".foo", { ".bar": 42 }]],
      expected: [["==", ".foo", { ".bar": 42 }]],
    },
    {
      case: "ne",
      input: [["!=", ".foo", { ".bar": 42 }]],
      expected: [["!=", ".foo", { ".bar": 42 }]],
    },
    {
      case: "anyOf1",
      input: [["anyOf", ".foo", [42, "hi"]]],
      expected: [["anyOf", ".foo", [42, "hi"]]],
    },
    {
      case: "anyOf2",
      input: [["anyOf", ".foo", [{ foo: 42 }]]],
      expected: [["anyOf", ".foo", [{ foo: 42 }]]],
    },
    {
      case: "and",
      input: [
        [
          "and",
          [
            ["==", ".foo", 42],
            ["!=", ".bar", false],
          ],
        ],
      ],
      expected: [
        [
          "and",
          [
            ["==", ".foo", 42],
            ["!=", ".bar", false],
          ],
        ],
      ],
    },
    {
      case: "or",
      input: [
        [
          "or",
          [
            ["==", ".foo", 42],
            ["!=", ".bar", false],
          ],
        ],
      ],
      expected: [
        [
          "or",
          [
            ["==", ".foo", 42],
            ["!=", ".bar", false],
          ],
        ],
      ],
    },
    {
      case: "not",
      input: [["not", ["==", ".foo", 42]]],
      expected: [["not", ["==", ".foo", 42]]],
    },
    {
      case: "nested",
      input: [
        [
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
      ],
      expected: [
        [
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
      ],
    },
    {
      case: "multiple rules implicit and",
      input: [
        ["==", ".foo", 42],
        ["!=", ".bar", false],
      ],
      expected: [
        ["==", ".foo", 42],
        ["!=", ".bar", false],
      ],
    },
    {
      case: "empty",
      input: [],
      expected: [],
    },
  ])("valid policy $case", ({ input, expected }) => {
    const result = Policy.Schema.parse(input);
    expect(result).toEqual(expected);
  });

  test.each([
    { case: "invalid rule - only_op", input: [["=="]] },
    { case: "invalid rule - invalid_op", input: [["hi", ".foo", []]] },
    { case: "invalid rule - no_value1", input: [["==", ".foo"]] },
    { case: "invalid rule - no_value2", input: [["!=", ".foo"]] },
    { case: "invalid rule - no_value3", input: [["anyOf", ".foo"]] },
    { case: "invalid rule - anyof_no_vec", input: [["anyOf", ".foo", 42]] },
    { case: "invalid rule - and_no_vec", input: [["and"]] },
    { case: "invalid rule - or_no_vec", input: [["or"]] },
    { case: "invalid rule - not_no_policy", input: [["not"]] },
    { case: "invalid rule - empty_and", input: [["and", []]] },
    { case: "invalid rule - empty_or", input: [["or", []]] },
    { case: "invalid rule - and_bogus_vec", input: [["and", ["hi"]]] },
    { case: "invalid rule - and_bogus_policy", input: [["and", [["hi"]]]] },
    { case: "invalid rule - not_bogus_policy", input: [["not", "hi"]] },
    { case: "not an array", input: "not a policy" },
    { case: "nested non-array", input: ["==", ".foo", 42] },
  ])("invalid policy $case", ({ input }) => {
    expect(() => Policy.Schema.parse(input)).toThrowError();
  });

  test.each([
    {
      case: "eq value",
      policy: Policy.Schema.parse([["==", ".name.first", "bob"]]),
    },
    {
      case: "ne",
      policy: Policy.Schema.parse([["!=", ".name.first", "john"]]),
    },
    {
      case: "eq object",
      policy: Policy.Schema.parse([
        ["==", ".name", { first: "bob", last: "smith" }],
      ]),
    },
    {
      case: "eq value context",
      policy: Policy.Schema.parse([["==", "$.req.foo", 42]]),
    },
    {
      case: "ne context",
      policy: Policy.Schema.parse([["!=", "$.other", 1335]]),
    },
    {
      case: "eq root",
      policy: Policy.Schema.parse([
        [
          "==",
          ".",
          {
            name: { first: "bob", last: "smith" },
            age: 42,
          },
        ],
      ]),
    },
    {
      case: "notEq",
      policy: Policy.Schema.parse([["!=", ".age", 150]]),
    },
    {
      case: "anyOf",
      policy: Policy.Schema.parse([["anyOf", ".name.first", ["john", "bob"]]]),
    },
    {
      case: "and",
      policy: Policy.Schema.parse([
        [
          "and",
          [
            ["==", ".age", 42],
            ["==", ".name.first", "bob"],
          ],
        ],
      ]),
    },
    {
      case: "or short circuit",
      policy: Policy.Schema.parse([
        [
          "or",
          [
            ["==", ".age", 42],
            ["==", ".age", 100],
          ],
        ],
      ]),
    },
    {
      case: "or long circuit",
      policy: Policy.Schema.parse([
        [
          "or",
          [
            ["==", ".age", 100],
            ["==", ".age", 42],
          ],
        ],
      ]),
    },
    {
      case: "implicit and with multiple rules",
      policy: Policy.Schema.parse([
        ["==", ".age", 42],
        ["==", ".name.first", "bob"],
      ]),
    },
  ])("evaluation matches $case", ({ policy }) => {
    const value = {
      name: {
        first: "bob",
        last: "smith",
      },
      age: 42,
    };
    const context = { req: { foo: 42, bar: "zar" }, other: 1337 };
    const result = Policy.evaluatePolicy(policy, value, context);
    expect(result).toBe(true);
  });

  test.each([
    {
      case: "eq value",
      policy: Policy.Schema.parse([["==", ".name.first", "john"]]),
    },
    {
      case: "ne",
      policy: Policy.Schema.parse([["!=", ".name.first", "bob"]]),
    },
    {
      case: "eq object",
      policy: Policy.Schema.parse([
        ["==", ".name", { first: "john", last: "smith" }],
      ]),
    },
    {
      case: "eq value context",
      policy: Policy.Schema.parse([["==", "$.req.foo", 43]]),
    },
    {
      case: "ne context",
      policy: Policy.Schema.parse([["!=", "$.other", 1337]]),
    },
    {
      case: "eq root",
      policy: Policy.Schema.parse([
        [
          "==",
          ".",
          {
            name: { first: "bob", last: "smith" },
            age: 100,
          },
        ],
      ]),
    },
    {
      case: "notEq",
      policy: Policy.Schema.parse([["!=", ".age", 42]]),
    },
    {
      case: "anyOf",
      policy: Policy.Schema.parse([["anyOf", ".name.first", ["john", "jack"]]]),
    },
    {
      case: "and1",
      policy: Policy.Schema.parse([
        [
          "and",
          [
            ["==", ".age", 150],
            ["==", ".name.first", "bob"],
          ],
        ],
      ]),
    },
    {
      case: "and2",
      policy: Policy.Schema.parse([
        [
          "and",
          [
            ["==", ".age", 42],
            ["==", ".name.first", "john"],
          ],
        ],
      ]),
    },
    {
      case: "or",
      policy: Policy.Schema.parse([
        [
          "or",
          [
            ["==", ".age", 101],
            ["==", ".age", 100],
          ],
        ],
      ]),
    },
  ])("evaluation does not match $case", ({ policy }) => {
    const value = {
      name: {
        first: "bob",
        last: "smith",
      },
      age: 42,
    };
    const context = { req: { foo: 42, bar: "zar" }, other: 1337 };
    const result = Policy.evaluatePolicy(policy, value, context);
    expect(result).toBe(false);
  });

  test.each([
    {
      case: "simple operator",
      policy: Policy.Schema.parse([["==", ".status", "active"]]),
      expected: { maxDepth: 1, maxWidth: 1 },
    },
    {
      case: "and connector",
      policy: Policy.Schema.parse([
        [
          "and",
          [
            ["==", ".status", "active"],
            ["!=", ".deleted", true],
          ],
        ],
      ]),
      expected: { maxDepth: 2, maxWidth: 2 },
    },
    {
      case: "nested policy",
      policy: Policy.Schema.parse([
        [
          "and",
          [
            ["==", ".status", "active"],
            [
              "or",
              [
                ["==", ".role", "admin"],
                ["==", ".role", "moderator"],
              ],
            ],
          ],
        ],
      ]),
      expected: { maxDepth: 3, maxWidth: 2 },
    },
    {
      case: "not connector",
      policy: Policy.Schema.parse([["not", ["==", ".status", "blocked"]]]),
      expected: { maxDepth: 2, maxWidth: 1 },
    },
    {
      case: "implicit and",
      policy: Policy.Schema.parse([
        ["==", ".status", "active"],
        ["!=", ".deleted", true],
      ]),
      expected: { maxDepth: 2, maxWidth: 2 },
    },
    {
      case: "deeply nested policies",
      policy: Policy.Schema.parse([
        [
          "or",
          [
            ["==", ".a", 1],
            [
              "and",
              [
                ["!=", ".b", 2],
                [
                  "or",
                  [
                    ["==", ".c", 3],
                    ["not", ["anyOf", ".d", [4, 5, 6]]],
                  ],
                ],
              ],
            ],
          ],
        ],
      ]),
      expected: { maxDepth: 5, maxWidth: 2 },
    },
  ])("getPolicyTreeProperties $case", ({ policy, expected }) => {
    const result = Policy.getPolicyTreeProperties(policy);
    expect(result).toEqual(expected);
  });
});
