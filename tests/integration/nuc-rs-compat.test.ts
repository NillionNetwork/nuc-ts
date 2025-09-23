import { describe, expect, it } from "vitest";
import { assertFailure, assertSuccess } from "#tests/helpers/assertions";
import { NucRsCompatAssertions } from "./nuc-rs-compat";

describe("nuc-rs compatibility tests", () => {
  it("should pass all nuc-rs test assertions", () => {
    for (const [index, assertion] of NucRsCompatAssertions.entries()) {
      const { input, expectation } = assertion;
      const config = {
        rootDids: input.rootKeys,
        currentTime: input.currentTime,
        parameters: input.parameters,
        context: input.context,
      };

      // indicating which assertion failed.
      expect(() => {
        if (expectation.result === "success") {
          assertSuccess(input.token, config);
        } else {
          assertFailure(input.token, expectation.kind, config);
        }
      }).toSatisfy(() => true, `Assertion ${index + 1} failed`);
    }
  });
});
