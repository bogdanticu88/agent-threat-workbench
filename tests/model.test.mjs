// Run with: node --test tests/
import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";

const src = f => readFileSync(new URL("../" + f, import.meta.url), "utf8");
const api = vm.runInNewContext(src("src/catalog.js") + "\n" + src("src/model.js") +
  "\n;({THREATS, CONTROLS, PATHS, compute, blankState, migrate, importAny, ctrlLevelOf, missingFor, profileToQuery, profileFromQuery, DEFAULT_WEIGHTS})", {URLSearchParams});
const sample = JSON.parse(src("examples/overreach-sample.json"));
const same = (a, b, msg) => assert.equal(JSON.stringify(a), JSON.stringify(b), msg);
const {compute, blankState, migrate, importAny, ctrlLevelOf, THREATS, CONTROLS, PATHS} = api;

const state = (feat = [], extra = {}) => { const s = blankState(); s.profile.feat = feat; return Object.assign(s, extra); };
const impl = (...ids) => Object.fromEntries(ids.map(id => [id, {lvl: 2}]));

test("catalogue references only real controls, detections and threats", () => {
  const C = new Set(CONTROLS.map(c => c.id)), T = new Set(THREATS.map(t => t.id));
  for (const t of THREATS){
    [...t.c, ...Object.values(t.reqIf || {}).flat(), ...(t.alt || []).flat(), ...(t.opt || [])].forEach(c => assert.ok(C.has(c), `${t.id} -> ${c}`));
    assert.ok(t.c.length || (t.alt || []).length || Object.keys(t.reqIf || {}).length, `${t.id} has no way to be mitigated`);
    (t.cases || []).forEach(c => assert.match(c.u, /^https:\/\//, `${t.id} case has a source link`));
  }
  for (const p of PATHS) p.stages.forEach(s => s[1].forEach(id => assert.ok(T.has(id), `${p.id} -> ${id}`)));
});

test("threats apply only when the profile has their prerequisites", () => {
  const M = compute(state(["tools"]));
  assert.equal(M.threats.T20.applies, false, "coding-agent threat needs coding agents");
  assert.equal(M.threats.T15.applies, true);
  assert.equal(compute(state(["coding"])).threats.T20.applies, true);
});

test("one-of groups: T07 is mitigated by TL-2 plus any one way to break the trifecta", () => {
  const feat = ["data", "untrusted", "tools"];
  assert.equal(compute(state(feat, {ctrl: impl("TL-2")})).threats.T07.status, "Partial");
  for (const alt of ["TL-3", "IN-1", "TL-7"])
    assert.equal(compute(state(feat, {ctrl: impl("TL-2", alt)})).threats.T07.status, "Mitigated", `via ${alt}`);
});

test("missing controls list required ones and unsatisfied groups", () => {
  const s = state(["data", "untrusted", "tools"]);
  const m = compute(s).threats.T07.missing;
  same(m.req, ["TL-2"]);
  same(m.groups, [["TL-3", "IN-1", "TL-7"]]);
});

test("Verified needs written evidence, otherwise it counts as Implemented", () => {
  const s = state([], {ctrl: {"ID-1": {lvl: 3, evidence: ""}}});
  assert.equal(ctrlLevelOf(s, "ID-1"), 2);
  assert.equal(compute(s).threats.T41.status, "Mitigated");
  s.ctrl["ID-1"].evidence = "MFA policy CA-07";
  assert.equal(compute(s).threats.T41.status, "Verified");
});

test("accepting risk records a decision but keeps the threat outstanding", () => {
  const s = state(["logging"], {accept: {T27: {owner: "CISO", reason: "x"}}});
  const m = compute(s).threats.T27;
  assert.equal(m.status, "Accepted");
  assert.equal(m.outstanding, true);
});

test("attack paths respect their prerequisites", () => {
  const ids = s => compute(s).paths.filter(p => p.applies).map(p => p.id);
  const base = ["data", "rag", "untrusted", "tools"];
  assert.ok(!ids(state(base)).includes("AP-5"), "AP-5 needs coding agents");
  assert.ok(ids(state([...base, "coding"])).includes("AP-5"));
  assert.ok(!ids(state(base)).includes("AP-4"), "AP-4 needs tenants or a shared MCP gateway");
  const mt = state(base); mt.profile.audience = "multitenant";
  assert.ok(ids(mt).includes("AP-4"));
  assert.equal(compute(mt).paths.find(p => p.id === "AP-4").t, "Cross-tenant tool execution");
  assert.equal(compute(state([...base, "mcp"])).paths.find(p => p.id === "AP-4").t, "Cross-user tool execution through a shared gateway");
});

test("a path breaks when one stage is fully mitigated, and detection never breaks it", () => {
  const feat = ["untrusted", "tools"];
  const open = state(feat, {det: {"DT-01": true, "DT-02": true, "DT-08": true}});
  const p1 = compute(open).paths.find(p => p.id === "AP-2");
  assert.equal(p1.applies, true); assert.equal(p1.blocked, false);
  assert.ok(p1.detOn.length >= 2, "detections are reported");
  // stage 3: T17 (approval) needs TL-5; T43 needs TL-4 plus a policy check or approval
  const fixed = state(feat, {ctrl: impl("TL-5", "TL-4")});
  const p2 = compute(fixed).paths.find(p => p.id === "AP-2");
  assert.equal(p2.blocked, true);
  assert.equal(p2.stages[2].blocked, true);
});

test("weights change ratings and can be restored", () => {
  const s = state(["tools"]); s.profile.autonomy = "auto";
  const before = compute(s).threats.T15.L;
  s.weights = {act: 0};
  assert.equal(compute(s).threats.T15.L, before - 1);
  s.weights = null;
  assert.equal(compute(s).threats.T15.L, before);
});

test("Overreach import keeps evidence grades and maps by outcome", () => {
  const fs = importAny(sample, "sample");
  assert.equal(fs.length, sample.chains.length);
  assert.ok(fs.every(f => f.grade === "reachable" && f.confirmed === true && f.mapBy === "outcome"));
  assert.ok(fs.every(f => f.threats.includes("T07")));
  const s = state(["data", "untrusted", "tools"], {findings: fs});
  const m = compute(s).threats.T07;
  assert.equal(m.reach, true); assert.equal(m.proven, false, "hypothetical is not proof");
});

test("keyword mappings are suggestions and do not count until confirmed", () => {
  const sarif = {runs: [{tool: {driver: {name: "otherscanner"}}, results: [{ruleId: "ssrf-in-fetch", message: {text: "memory and prompt injection words in free text are ignored"}, properties: {evidence: "validated"}}]}]};
  const [f] = importAny(sarif, "x");
  assert.equal(f.mapBy, "keyword"); assert.equal(f.confirmed, false);
  same(f.threats, ["T14"], "only the rule id is used, not the message text");
  const s = state(["tools"], {findings: [f]});
  assert.equal(compute(s).threats.T14.proven, false);
  f.confirmed = true;
  assert.equal(compute(s).threats.T14.proven, true);
});

test("validated finding on a mitigated threat is flagged as a conflict", () => {
  const f = importAny({findings: [{title: "x", threats: ["T14"], evidence: "validated"}]}, "x");
  const s = state(["tools"], {findings: f, ctrl: impl("TL-7")});
  const m = compute(s).threats.T14;
  assert.equal(m.status, "Contradicted"); assert.equal(m.conflict, true); assert.equal(m.outstanding, true);
});

test("v1 saved state migrates without losing findings", () => {
  const v1 = {profile: {host: "api", autonomy: "approve", audience: "internal", feat: ["tools"]}, ctrl: {"TL-1": {lvl: 2}}, findings: [{tool: "overreach", id: "a", threats: ["T15"], grade: "reachable"}]};
  const s = migrate(v1);
  assert.equal(s.v, 2);
  assert.equal(s.findings[0].confirmed, true);
  assert.equal(s.ctrl["TL-1"].lvl, 2);
  assert.equal(migrate({nope: 1}), null);
});

test("profile round-trips through a link", () => {
  const p = {host: "platform", autonomy: "auto", audience: "multitenant", feat: ["tools", "mcp"]};
  const back = api.profileFromQuery(api.profileToQuery(p, {path: "AP-4"}));
  assert.equal(back.host, "platform"); assert.equal(back.audience, "multitenant");
  same(back.feat, ["tools", "mcp"]); assert.equal(back.path, "AP-4");
  assert.equal(api.profileFromQuery("?f=tools,evil").feat.join(), "tools", "unknown features are dropped");
});

// ---------- regressions from the v0.3 review ----------

test("regression: a validated exploit stops a path from counting as broken", () => {
  const feat = ["untrusted", "tools"];
  const s = state(feat, {ctrl: impl("TL-5", "TL-4")});
  assert.equal(compute(s).paths.find(p => p.id === "AP-2").blocked, true);
  s.findings = importAny({findings: [{title: "unapproved transfer replayed", threats: ["T43"], evidence: "validated"}]}, "x");
  const M = compute(s);
  assert.equal(M.threats.T43.status, "Contradicted");
  assert.equal(M.paths.find(p => p.id === "AP-2").blocked, false, "proof beats checkboxes");
});

test("regression: output encoding alone does not break the autonomous-action path", () => {
  const s = state(["untrusted", "tools"], {ctrl: impl("OUT-1")}); s.profile.autonomy = "auto";
  const p = compute(s).paths.find(p => p.id === "AP-2");
  assert.equal(p.applies, true); assert.equal(p.blocked, false);
  s.ctrl = impl("TL-4", "TL-2");
  assert.equal(compute(s).paths.find(p => p.id === "AP-2").blocked, true, "a policy check outside the model with action limits does break it");
});

test("regression: retrieval ACLs do not mitigate memory leakage", () => {
  const mem = state(["memory"], {ctrl: impl("DA-1")});
  assert.notEqual(compute(mem).threats.T25.status, "Mitigated");
  mem.ctrl = impl("DA-5");
  assert.equal(compute(mem).threats.T25.status, "Mitigated");
  const both = state(["memory", "rag"], {ctrl: impl("DA-5")});
  assert.notEqual(compute(both).threats.T25.status, "Mitigated", "retrieval also needs its own isolation");
  both.ctrl = impl("DA-5", "DA-1");
  assert.equal(compute(both).threats.T25.status, "Mitigated");
  same(compute(both).threats.T25.missing.req, []);
});

test("regression: malformed assessments are cleaned or refused, never crash", () => {
  const bad = {v: 2, profile: {host: "nope", autonomy: 7, audience: null, feat: "tools"}, findings: null, ctrl: {"TL-1": {lvl: "x"}, "ZZ-9": {lvl: 2}},
    det: [], accept: {T01: "yes", T02: {owner: 5}}, snapshots: {}, weights: {act: 99, bands: [1], rank: {High: "a"}}};
  const s = migrate(bad);
  assert.ok(s);
  same(s.findings, []); same(s.profile.feat, []); assert.equal(s.profile.host, "api");
  assert.equal(s.ctrl["TL-1"].lvl, 0); assert.equal(s.ctrl["ZZ-9"], undefined);
  assert.equal(s.accept.T01, undefined); assert.equal(s.weights, null);
  assert.doesNotThrow(() => compute(s));
  const f = migrate({profile: {feat: ["tools"]}, findings: [null, 3, {threats: null}, {threats: ["T15", "BAD"], grade: "proven"}]});
  assert.equal(f.findings.length, 2); same(f.findings[1].threats, ["T15"]);
  assert.doesNotThrow(() => compute(f));
  for (const junk of [null, 3, "x", [], {profile: null}, {profile: []}]) assert.equal(migrate(junk), null);
});
