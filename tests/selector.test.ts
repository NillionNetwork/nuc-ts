import { describe, it } from "vitest";
import { applySelector } from "#/selector";
import { OperatorSchema, SelectorSchema } from "#/types";

describe.each([
  { test: "identity", input: ".", path: [] },
  { test: "single", input: ".foo", path: ["foo"] },
  { test: "multi", input: ".foo.bar", path: ["foo", "bar"] },
  {
    test: "entire_alphabet",
    input: ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    path: ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"],
  },
])("valid policy", ({ test, input, path }) => {
  it(`${test}`, ({ expect }) => {
    const result = SelectorSchema.parse(input);
    expect(result).toEqual(path);
  });
});

describe.each([
  { test: "empty", input: "" },
  { test: "no_leading_dot", input: "A" },
  { test: "invalid_field_name1", input: ".#" },
  { test: "invalid_field_name2", input: ".🚀" },
  { test: "trailing_dot", input: ".A." },
  { test: "empty_label", input: ".A..B" },
])("invalid policy", ({ test, input }) => {
  it(`${test}`, ({ expect }) => {
    expect(() => OperatorSchema.parse(input)).toThrowError();
  });
});

describe.each([
  {
    test: "identity",
    selector: ".",
    input: { foo: 42 },
    expected: { foo: 42 },
  },
  { test: "field", selector: ".foo", input: { foo: 42 }, expected: 42 },
  {
    test: "nested",
    selector: ".foo.bar",
    input: { foo: { bar: 42 } },
    expected: 42,
  },
  { test: "non_existent", selector: ".foo", input: { bar: 42 } },
])("lookup", ({ test, selector, input, expected }) => {
  it(`${test}`, ({ expect }) => {
    const result = applySelector(SelectorSchema.parse(selector), input);
    expect(result).toEqual(expected);
  });
});
