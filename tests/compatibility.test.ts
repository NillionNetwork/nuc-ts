import { describe, it } from "vitest";
import { NucTokenValidator } from "#/validate";
import { TEST_ASSERTIONS } from "./fixture/assertions";

describe("nuc-rs compatibility tests", () => {
  TEST_ASSERTIONS.forEach((assertion, index) => {
    it(`test assertion ${index + 1}`, ({ expect }) => {
      const { input, expectation } = assertion;
      const errorMessage =
        expectation.result === "failure" ? expectation.kind : "";
      try {
        const validator = new NucTokenValidator(
          input.rootKeys,
          () => input.currentTime,
        );
        validator.validate(input.token, input.parameters, input.context);
        expect(
          "success",
          `succeeded but expected failure: ${errorMessage}`,
        ).toBe(expectation.result);
      } catch (e) {
        if (e instanceof Error) {
          expect("failure", `expected success but failed: ${e.message}`).toBe(
            expectation.result,
          );
          expect(
            e.message,
            `failed with unexpected error: expected ${errorMessage}, got ${e.message}`,
          ).toBe(errorMessage);
        }
      }
    });
  });
});
