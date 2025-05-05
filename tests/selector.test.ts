import { describe, it } from "vitest";
import { Selector, SelectorSchema, type SelectorTarget } from "#/selector";

describe.each([
  { test: "identity", input: ".", path: [], target: "token" },
  { test: "single", input: ".foo", path: ["foo"], target: "token" },
  { test: "single context", input: "$.foo", path: ["foo"], target: "context" },
  { test: "multi", input: ".foo.bar", path: ["foo", "bar"], target: "token" },
  {
    test: "multi context",
    input: "$.foo.bar",
    path: ["foo", "bar"],
    target: "context",
  },
  {
    test: "entire_alphabet",
    input: ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    path: ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"],
    target: "token",
  },
])("valid policy", ({ test, input, path, target }) => {
  it(`${test}`, ({ expect }) => {
    const result = SelectorSchema.parse(input);
    expect(result).toEqual(new Selector(path, target as SelectorTarget));
  });
});

describe.each([
  // { test: "empty", input: "" },
  // { test: "empty context", input: "$" },
  { test: "empty context 2", input: "$." },
  // { test: "no_leading_dot", input: "A" },
  // { test: "invalid_field_name1", input: ".#" },
  // { test: "invalid_field_name2", input: ".🚀" },
  // { test: "invalid_field_context_name1", input: "$.#" },
  // { test: "invalid_field_context_name2", input: "$.$" },
  // { test: "trailing_dot", input: ".A." },
  // { test: "empty_label", input: ".A..B" },
  // { test: "empty_label_context", input: "$.A..B" },
])("invalid policy", ({ test, input }) => {
  it(`${test}`, ({ expect }) => {
    expect(() => SelectorSchema.parse(input)).toThrowError();
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
    const result = SelectorSchema.parse(selector).apply(input, {});
    expect(result).toEqual(expected);
  });
});

describe.each([
  {
    test: "object",
    selector: "$.req",
    expected: { foo: 42, bar: "zar" },
  },
  { test: "value", selector: "$.other", expected: 1337 },
  { test: "nested", selector: "$.req.foo", expected: 42 },
  { test: "undefined", selector: "$.foo", expected: undefined },
  { test: "undefined nested", selector: "$.req.choochoo", expected: undefined },
  { test: "boolean", selector: "$.bool", expected: false },
])("lookup context", ({ test, selector, expected }) => {
  it(`${test}`, ({ expect }) => {
    const context = { req: { foo: 42, bar: "zar" }, other: 1337, bool: false };
    const result = SelectorSchema.parse(selector).apply(undefined, context);
    expect(result).toEqual(expected);
  });
});
