import { type Command, Payload } from "#/nuc/payload";
import { describe, expect, it } from "vitest";

describe("isCommandAttenuationOf", () => {
  it.each([
    ["/a/b", "/a", true],
    ["/a", "/", true],
    ["/a/b", "/a/b", true],
    ["/a", "/a/b", false],
    ["/x", "/y", false],
  ])('should return %s for command "%s" and parent "%s"', (cmd, parent, expected) => {
    expect(Payload.isCommandAttenuationOf(cmd as Command, parent as Command)).toBe(expected);
  });
});
