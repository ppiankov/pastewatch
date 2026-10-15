import { strict as assert } from "node:assert";
import { test } from "node:test";

import { canOfferProjectExemption } from "./projectExemption";

// WO-682@v2: the editor offers an exemption only for an explicitly eligible finding.
test("offer a project exemption when the CLI flag is true", () => {
  assert.equal(canOfferProjectExemption(true), true);
});

// WO-682@v2: missing, negative and malformed metadata cannot authorize an editor action.
for (const value of [false, undefined, null, "true", 1, {}, new Boolean(true)]) {
  test(`do not offer a project exemption for ${typeof value} metadata`, () => {
    assert.equal(canOfferProjectExemption(value), false);
  });
}
