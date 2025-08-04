import { describe, expect, it } from "vitest";
import { Asserter, TEST_ASSERTIONS } from "./assertions";

describe("nuc-rs compatibility tests", () => {
  it("should pass all nuc-rs test assertions", () => {
    for (const [index, assertion] of TEST_ASSERTIONS.entries()) {
      const { input, expectation } = assertion;
      const asserter = new Asserter({
        rootDids: input.rootKeys,
        currentTime: input.currentTime,
        parameters: input.parameters,
        context: input.context,
      });

      // Using expect().toSatisfy() provides a clear failure message
      // indicating which assertion failed.
      expect(() => {
        if (expectation.result === "success") {
          asserter.assertSuccess(input.token);
        } else {
          asserter.assertFailure(input.token, expectation.kind);
        }
      }).toSatisfy(() => true, `Assertion ${index + 1} failed`);
    }
  });
});
