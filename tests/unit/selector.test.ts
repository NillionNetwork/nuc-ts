import { describe, expect, test } from "vitest";
import { applySelector, SelectorSchema } from "#/nuc/selector";

describe("Selector", () => {
  test.each([
    { case: "identity token", input: "." },
    { case: "identity context", input: "$." },
    { case: "single", input: ".foo" },
    { case: "single context", input: "$.foo" },
    { case: "multi", input: ".foo.bar" },
    { case: "multi context", input: "$.foo.bar" },
    {
      case: "entire_alphabet",
      input:
        ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    },
  ])("select $case ($input)", ({ input }) => {
    expect(() => SelectorSchema.parse(input)).not.toThrowError();
  });

  test.each([
    { case: "empty", input: "" },
    { case: "empty context", input: "$" },
    { case: "no_leading_dot", input: "A" },
    { case: "invalid_field_name1", input: ".#" },
    { case: "invalid_field_name2", input: ".🚀" },
    { case: "invalid_field_context_name1", input: "$.#" },
    { case: "invalid_field_context_name2", input: "$.$" },
    { case: "trailing_dot", input: ".A." },
    { case: "empty_label", input: ".A..B" },
    { case: "empty_label_context", input: "$.A..B" },
  ])("select $case", ({ input }) => {
    expect(() => SelectorSchema.parse(input)).toThrowError();
  });

  test.each([
    {
      case: "identity",
      selector: ".",
      input: { foo: 42 },
      expected: { foo: 42 },
    },
    { case: "field", selector: ".foo", input: { foo: 42 }, expected: 42 },
    {
      case: "nested",
      selector: ".foo.bar",
      input: { foo: { bar: 42 } },
      expected: 42,
    },
    { case: "non_existent", selector: ".foo", input: { bar: 42 } },
  ])("lookup $case", ({ selector, input, expected }) => {
    const parsedSelector = SelectorSchema.parse(selector);
    const result = applySelector(parsedSelector, input, {});
    expect(result).toEqual(expected);
  });

  test.each([
    {
      case: "object",
      selector: "$.req",
      expected: { foo: 42, bar: "zar" },
    },
    { case: "value", selector: "$.other", expected: 1337 },
    { case: "nested", selector: "$.req.foo", expected: 42 },
    { case: "undefined", selector: "$.foo", expected: undefined },
    {
      case: "undefined nested",
      selector: "$.req.choochoo",
      expected: undefined,
    },
    { case: "boolean", selector: "$.bool", expected: false },
  ])("lookup $case", ({ selector, expected }) => {
    const context = {
      req: { foo: 42, bar: "zar" },
      other: 1337,
      bool: false,
    };

    const parsedSelector = SelectorSchema.parse(selector);
    const result = applySelector(parsedSelector, {}, context);
    expect(result).toEqual(expected);
  });
});
