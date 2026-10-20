import assert from "node:assert/strict";
import { test } from "node:test";
import { aclDraftEntries, aclDraftError } from "../src/aclDraft.ts";

const blank = { id: "entry", priority: 10, action: "deny", cidrs: [] };

test("geographic ACL requires an explicit unknown action without seeding any matches", () => {
  assert.equal(aclDraftError([blank]), "");
  const empty = aclDraftEntries([blank])[0];
  assert.equal(empty.countries, undefined);
  assert.equal(empty.regions, undefined);
  assert.equal(empty.cidrs, undefined);
  assert.equal(empty.geo_unknown_action, undefined);
  const regional = { ...blank, countries: ["ZZ"], regions: ["ZZ-CUSTOM"] };
  assert.match(aclDraftError([regional]), /必须明确选择/);
  for (const geo_unknown_action of ["deny", "no_match"] as const) {
    const entry = { ...regional, geo_unknown_action };
    assert.equal(aclDraftError([entry]), "");
    assert.deepEqual(aclDraftEntries([entry])[0].regions, ["ZZ-CUSTOM"]);
    assert.equal(
      aclDraftEntries([entry])[0].geo_unknown_action,
      geo_unknown_action,
    );
  }
  assert.equal(
    aclDraftEntries([{ ...blank, geo_unknown_action: "deny" }])[0]
      .geo_unknown_action,
    undefined,
  );
});

test("draft validation rejects malformed geography, duplicate priorities and invalid ports", () => {
  assert.match(aclDraftError([{ ...blank, countries: ["zz"] }]), /国家代码/);
  assert.match(
    aclDraftError([{ ...blank, regions: ["ZZ-region"] }]),
    /国家代码/,
  );
  assert.match(aclDraftError([blank, { ...blank, id: "another" }]), /不重复/);
  assert.match(aclDraftError([{ ...blank, ports: [0] }]), /端口/);
});
