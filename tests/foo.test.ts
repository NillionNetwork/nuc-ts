import { describe, it } from "vitest"
import {foo} from "#/lib";

describe('its alive', () => {
  it("foo is bar", ({ expect }) => {
    expect(foo()).toBe("bar")
  })
});
