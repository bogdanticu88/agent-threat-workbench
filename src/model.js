// Pure model: no DOM. Used by the page and by the tests.
const SCHEMA = 2;
const LEVELS = ["Not in place", "Partial", "Implemented", "Verified"];
const DEFAULT_WEIGHTS = {
  act: 1,          // likelihood change for action threats when the agent acts on its own (and -1 when it only suggests)
  exposed: 1,      // likelihood change for exposure threats when users are outside the company
  data: 1,         // impact change for data threats when sensitive data is in scope
  mt: 2,           // likelihood change for tenant threats in a multi-tenant service
  bands: [20, 12, 6], // score thresholds for Critical, High, Medium (score = likelihood x impact)
  rank: {Critical: 4, High: 3, Medium: 2, Low: 1}, // weight of an outstanding threat when ranking controls
  altShare: 0.5,   // share of that weight a control earns when it is one of several alternatives
  path: 3,         // bonus per open path where the control sits on the stage with the fewest missing controls
  prio: true       // add a small bonus for P1 over P2 over P3
};

const CTRL = Object.fromEntries(CONTROLS.map(c => [c.id, c]));
const THR = Object.fromEntries(THREATS.map(t => [t.id, t]));
const DET = Object.fromEntries(DETECTIONS.map(d => [d[0], d]));

function blankState(){
  return {v: SCHEMA, profile: {host: "api", autonomy: "approve", audience: "internal", feat: []}, ctrl: {}, det: {}, accept: {}, findings: [], snapshots: [], weights: null, example: false};
}

// Rebuild a saved or imported state field by field. Anything malformed is dropped or reset, never trusted.
// Returns null when there is no usable profile, so a bad file can never replace the current assessment.
function migrate(s){
  const isObj = x => x && typeof x === "object" && !Array.isArray(x);
  if (!isObj(s) || !isObj(s.profile)) return null;
  const pick = (v, list, d) => list.some(x => x[0] === v) ? v : d;
  const keys = FEATURES.map(f => f[0]);
  const p = s.profile;
  const out = blankState();
  out.profile = {host: pick(p.host, HOSTING, "api"), autonomy: pick(p.autonomy, AUTONOMY, "approve"), audience: pick(p.audience, AUDIENCE, "internal"),
    feat: Array.isArray(p.feat) ? keys.filter(k => p.feat.includes(k)) : []};
  const str = v => typeof v === "string" ? v.slice(0, 2000) : "";
  if (isObj(s.ctrl)) for (const [id, c] of Object.entries(s.ctrl)) if (CTRL[id] && isObj(c)){
    const lvl = Number.isInteger(c.lvl) && c.lvl >= 0 && c.lvl <= 3 ? c.lvl : 0;
    out.ctrl[id] = {lvl, owner: str(c.owner), evidence: str(c.evidence)};
  }
  if (isObj(s.det)) for (const [id, on] of Object.entries(s.det)) if (DET[id]) out.det[id] = on === true;
  if (isObj(s.accept)) for (const [id, a] of Object.entries(s.accept)) if (THR[id] && isObj(a)) out.accept[id] = {owner: str(a.owner), reason: str(a.reason), expiry: str(a.expiry)};
  const v1 = !s.v || s.v < 2;
  if (Array.isArray(s.findings)) out.findings = s.findings.filter(isObj).map(f => ({
    tool: str(f.tool) || "findings", id: str(String(f.id ?? "")), title: str(f.title), detail: str(f.detail), evidence: str(f.evidence),
    grade: ["proven", "simulated", "reachable", "reported"].includes(f.grade) ? f.grade : "reported",
    impact: Number.isFinite(f.impact) ? f.impact : undefined, notes: Array.isArray(f.notes) ? f.notes.filter(x => typeof x === "string") : [],
    threats: Array.isArray(f.threats) ? [...new Set(f.threats.filter(id => THR[id]))] : [],
    // v1 findings came from Overreach outcomes or explicit lists, so they count as confirmed
    mapBy: ["outcome", "explicit", "keyword"].includes(f.mapBy) ? f.mapBy : (v1 ? "outcome" : "explicit"),
    confirmed: v1 ? true : f.confirmed !== false, source: str(f.source), key: str(f.key) || (str(f.tool) + ":" + str(String(f.id ?? "")))
  }));
  if (Array.isArray(s.snapshots)) out.snapshots = s.snapshots.filter(isObj).map(x => ({label: str(x.label), date: str(x.date),
    outstanding: +x.outstanding || 0, mitigated: +x.mitigated || 0, openPaths: +x.openPaths || 0}));
  if (isObj(s.weights)){
    const w = {}, n = (v, lo, hi) => Number.isFinite(v) && v >= lo && v <= hi;
    ["act", "exposed", "data", "mt"].forEach(k => { if (n(s.weights[k], 0, 5)) w[k] = s.weights[k]; });
    if (n(s.weights.altShare, 0, 1)) w.altShare = s.weights.altShare;
    if (n(s.weights.path, 0, 10)) w.path = s.weights.path;
    if (typeof s.weights.prio === "boolean") w.prio = s.weights.prio;
    if (Array.isArray(s.weights.bands) && s.weights.bands.length === 3 && s.weights.bands.every(b => n(b, 1, 25))) w.bands = s.weights.bands.slice();
    if (isObj(s.weights.rank)){ const r = {}; ["Critical", "High", "Medium", "Low"].forEach(k => { if (n(s.weights.rank[k], 0, 10)) r[k] = s.weights.rank[k]; }); if (Object.keys(r).length) w.rank = r; }
    out.weights = Object.keys(w).length ? w : null;
  }
  out.example = s.example === true;
  out.v = SCHEMA;
  return out;
}

function weightsOf(S){ return Object.assign({}, DEFAULT_WEIGHTS, S.weights || {}, {rank: Object.assign({}, DEFAULT_WEIGHTS.rank, (S.weights || {}).rank || {})}); }

function ctrlLevelOf(S, id){
  const c = S.ctrl[id]; if (!c) return 0;
  if (c.lvl === 3 && !String(c.evidence || "").trim()) return 2; // Verified needs written evidence
  return c.lvl || 0;
}

// Required controls, including those that only apply because the profile has a feature (memory, retrieval, tools).
function requiredFor(t, p){
  const F = new Set(p.feat), extra = [];
  for (const k in (t.reqIf || {})) if (F.has(k)) t.reqIf[k].forEach(c => extra.includes(c) || t.c.includes(c) || extra.push(c));
  return [...t.c, ...extra];
}

// Which controls a threat still needs: every required one, plus one from each unsatisfied group of alternatives.
function missingFor(S, t){
  const req = requiredFor(t, S.profile).filter(c => ctrlLevelOf(S, c) < 2);
  const groups = (t.alt || []).filter(g => Math.max(...g.map(c => ctrlLevelOf(S, c))) < 2);
  return {req, groups, count: req.length + groups.length};
}

function threatStatus(S, t){
  const req = requiredFor(t, S.profile);
  const lv = [...req.map(c => ctrlLevelOf(S, c)), ...(t.alt || []).map(g => Math.max(...g.map(c => ctrlLevelOf(S, c))))];
  const touched = [...req, ...(t.alt || []).flat()].some(c => ctrlLevelOf(S, c) > 0);
  if (!lv.length) return "Open";
  const min = Math.min(...lv);
  return min >= 3 ? "Verified" : min >= 2 ? "Mitigated" : touched ? "Partial" : "Open";
}

function applies(t, p){
  const F = new Set(p.feat);
  if (t.req && !t.req.every(k => F.has(k))) return false;
  if (t.any && !t.any.some(k => F.has(k))) return false;
  if (t.when) for (const k in t.when) if (!t.when[k].includes(p[k])) return false;
  return true;
}

function compute(S){
  const p = S.profile, F = new Set(p.feat), W = weightsOf(S);
  const band = sc => sc >= W.bands[0] ? "Critical" : sc >= W.bands[1] ? "High" : sc >= W.bands[2] ? "Medium" : "Low";
  const clamp = v => Math.max(1, Math.min(5, v));
  const M = {threats: {}, ctrlNeed: {}, paths: [], findingsByThreat: {}, W};
  for (const f of S.findings) if (f.confirmed !== false) for (const tid of f.threats) (M.findingsByThreat[tid] ||= []).push(f);

  for (const t of THREATS){
    const ap = applies(t, p);
    let L = t.L, I = t.I; const why = [], mod = t.mod || [];
    if (mod.includes("act") && p.autonomy === "auto" && W.act){ L += W.act; why.push(`Acts on its own: likelihood +${W.act}`); }
    if (mod.includes("act") && p.autonomy === "suggest" && W.act){ L -= W.act; why.push(`Suggests only: likelihood -${W.act}`); }
    if (mod.includes("exposed") && p.audience !== "internal" && W.exposed){ L += W.exposed; why.push(`Outside users: likelihood +${W.exposed}`); }
    if (mod.includes("data") && F.has("data") && W.data){ I += W.data; why.push(`Sensitive data: impact +${W.data}`); }
    if (mod.includes("mt") && p.audience === "multitenant" && W.mt){ L += W.mt; why.push(`Multi-tenant: likelihood +${W.mt}`); }
    L = clamp(L); I = clamp(I);
    const score = L * I, risk = band(score);
    let status = threatStatus(S, t);
    const fs = M.findingsByThreat[t.id] || [];
    const proven = fs.some(f => f.grade === "proven");
    // A validated exploit outranks the checkboxes: the threat is not mitigated, whatever the controls say.
    const conflict = (status === "Mitigated" || status === "Verified") && proven;
    if (conflict) status = "Contradicted";
    if (S.accept[t.id] && !(status === "Mitigated" || status === "Verified")) status = status === "Contradicted" ? status : "Accepted";
    const outstanding = ap && !(status === "Mitigated" || status === "Verified");
    M.threats[t.id] = {applies: ap, L, I, score, risk, why, status, outstanding, proven, reach: fs.length > 0,
      conflict, findings: fs,
      missing: missingFor(S, t), detDeployed: t.d.filter(d => S.det[d]).length};
    if (ap) [...requiredFor(t, p), ...(t.alt || []).flat(), ...(t.opt || [])].forEach(c => { (M.ctrlNeed[c] ||= []).includes(t.id) || M.ctrlNeed[c].push(t.id); });
  }

  for (const ap of PATHS){
    const gate = (!ap.req || ap.req.every(k => F.has(k))) && (!ap.any || ap.any.some(k => F.has(k))) && (!ap.cond || ap.cond(p));
    const mt = p.audience === "multitenant";
    const title = (!mt && ap.tAlt) ? ap.tAlt : ap.t;
    const stages = ap.stages.map(([name0, ids, nameAlt], i) => {
      const name = (!mt && nameAlt) ? nameAlt : name0;
      const app = ids.filter(id => M.threats[id].applies);
      const blocked = app.length > 0 && app.every(id => !M.threats[id].outstanding);
      const req = new Set(), groups = [];
      app.forEach(id => { const m = M.threats[id].missing; m.req.forEach(c => req.add(c)); m.groups.forEach(g => { if (!groups.some(x => x.join() === g.join())) groups.push(g); }); });
      // a group already covered by a required control on the same stage needs nothing extra
      const openGroups = groups.filter(g => !g.some(c => req.has(c)));
      return {name, ids, app, blocked, missing: [...req], missingGroups: openGroups, cost: req.size + openGroups.length,
        evidence: app.some(id => M.threats[id].reach), anchor: (ap.anchors || [])[i]};
    });
    const isApplicable = gate && stages.every(s => s.app.length > 0);
    const blocked = isApplicable && stages.some(s => s.blocked);
    let cheapest = null;
    if (isApplicable && !blocked) cheapest = stages.reduce((a, s, i) => (a === null || s.cost < stages[a].cost) ? i : a, null);
    const dets = [...new Set(stages.flatMap(s => s.app.flatMap(id => THR[id].d)))];
    M.paths.push({...ap, t: title, gate, stages, applies: isApplicable, blocked, cheapest, dets, detOn: dets.filter(d => S.det[d]),
      evidenceStages: stages.filter(s => s.evidence).length});
  }

  // Rank controls that are not yet Implemented by how much outstanding risk they would help close.
  const lev = [];
  for (const cid in M.ctrlNeed){
    if (ctrlLevelOf(S, cid) >= 2) continue;
    let w = 0; const ts = [];
    for (const id of M.ctrlNeed[cid]){
      const m = M.threats[id]; if (!m.outstanding) continue;
      if (m.missing.req.includes(cid)){ w += W.rank[m.risk]; ts.push(id); }
      else if (m.missing.groups.some(g => g.includes(cid))){ w += W.rank[m.risk] * W.altShare; ts.push(id); }
    }
    if (!ts.length) continue;
    const pathBreaks = M.paths.filter(p => p.applies && !p.blocked && p.cheapest !== null &&
      (p.stages[p.cheapest].missing.includes(cid) || p.stages[p.cheapest].missingGroups.some(g => g.includes(cid)))).length;
    const prio = W.prio ? (4 - CTRL[cid].p) * 0.1 : 0;
    lev.push({cid, ts, w, pathBreaks, score: w + pathBreaks * W.path + prio});
  }
  lev.sort((a, b) => b.score - a.score || a.cid.localeCompare(b.cid));
  M.leverage = lev;
  M.app = THREATS.filter(t => M.threats[t.id].applies);
  M.count = fn => M.app.filter(t => fn(M.threats[t.id])).length;
  return M;
}

// ---------- findings import ----------
function gradeOf(ev){ ev = String(ev || "").toLowerCase(); return ev === "validated" ? "proven" : ev === "simulated" ? "simulated" : ev === "hypothetical" ? "reachable" : "reported"; }
function boundaryThreats(bs){ const ts = new Set(); (bs || []).forEach(b => BOUNDARY_RULES.forEach(([re, ids]) => { if (re.test(b)) ids.forEach(i => ts.add(i)); })); return ts; }
function keywordThreats(txt){ const ts = new Set(); for (const [re, ids] of KEYWORD_RULES) if (re.test(txt)) ids.forEach(i => ts.add(i)); return ts; }

function importAny(obj, source){
  const out = [];
  const add = f => { f.threats = [...new Set(f.threats)].filter(id => THR[id]); f.source = source; f.key = f.tool + ":" + f.id; if (f.confirmed === undefined) f.confirmed = f.mapBy !== "keyword"; out.push(f); };
  if (obj && Array.isArray(obj.chains)){ // Overreach JSON
    for (const c of obj.chains){
      const ts = new Set(OVERREACH_MAP[c.outcome] || []); boundaryThreats(c.boundaries).forEach(i => ts.add(i));
      add({tool: "overreach", id: c.id, title: (c.outcome || "").replace(/_/g, " ") + " via " + ((c.steps || []).slice(-1)[0]?.op || "?"),
        grade: gradeOf(c.evidence), evidence: c.evidence, impact: c.impact, detail: (c.steps || []).map(s => s.op).join("  >  "), notes: c.boundaries || [], threats: [...ts], mapBy: "outcome"});
    }
    return out;
  }
  if (obj && Array.isArray(obj.runs)){ // SARIF 2.1.0
    for (const run of obj.runs){
      const tool = run.tool?.driver?.name || "sarif";
      for (const r of run.results || []){
        const pr = r.properties || {}; let ts = new Set(); let mapBy = "explicit";
        const outcome = (r.ruleId || "").split("/").pop();
        (pr.threats || pr.atw_threats || []).forEach(i => ts.add(i));
        if (!ts.size && tool === "overreach" && OVERREACH_MAP[outcome]){ OVERREACH_MAP[outcome].forEach(i => ts.add(i)); boundaryThreats(pr.boundaries).forEach(i => ts.add(i)); mapBy = "outcome"; }
        // Keyword matching only looks at the rule id and tags, never free text, and is only a suggestion.
        if (!ts.size){ ts = keywordThreats([r.ruleId, ...(pr.tags || [])].join(" ")); mapBy = "keyword"; }
        add({tool, id: r.partialFingerprints ? Object.values(r.partialFingerprints)[0] : (r.ruleId + "-" + out.length), title: r.ruleId || "result",
          grade: gradeOf(pr.evidence), evidence: pr.evidence || r.level || "", impact: pr.impact, detail: (pr.path || []).join("  >  ") || (r.message?.text || "").slice(0, 240), notes: [], threats: [...ts], mapBy});
      }
    }
    return out;
  }
  const list = Array.isArray(obj) ? obj : Array.isArray(obj?.findings) ? obj.findings : null;
  if (list){
    list.forEach((f, i) => {
      let ts = new Set(f.threats || (f.threat ? [f.threat] : [])), mapBy = "explicit";
      if (!ts.size){ ts = keywordThreats([f.title, ...(f.tags || [])].join(" ")); mapBy = "keyword"; }
      add({tool: f.tool || obj.tool || "findings", id: f.id || ("F" + (i + 1)), title: f.title || "finding", grade: gradeOf(f.evidence), evidence: f.evidence || "", impact: f.impact, detail: f.description || "", notes: f.tags || [], threats: [...ts], mapBy});
    });
    return out;
  }
  throw new Error("Not recognised. Expected Overreach JSON, SARIF 2.1.0, or {\"findings\": [...]}.");
}

// ---------- profile in a link ----------
const FEATURE_KEYS = () => FEATURES.map(f => f[0]);
function profileToQuery(p, extra){
  const q = new URLSearchParams({h: p.host, a: p.autonomy, u: p.audience, f: p.feat.join(",")});
  if (extra) for (const k in extra) if (extra[k]) q.set(k, extra[k]);
  return q.toString();
}
function profileFromQuery(qs){
  const q = new URLSearchParams(qs); if (!q.has("h") && !q.has("f")) return null;
  const pick = (v, list, d) => list.some(x => x[0] === v) ? v : d;
  const keys = FEATURE_KEYS();
  return {host: pick(q.get("h"), HOSTING, "api"), autonomy: pick(q.get("a"), AUTONOMY, "approve"), audience: pick(q.get("u"), AUDIENCE, "internal"),
    feat: (q.get("f") || "").split(",").filter(k => keys.includes(k)), path: q.get("path") || "", view: q.get("view") || ""};
}

if (typeof module !== "undefined") module.exports = {SCHEMA, LEVELS, DEFAULT_WEIGHTS, blankState, migrate, weightsOf, ctrlLevelOf, missingFor, requiredFor, threatStatus, applies, compute, importAny, gradeOf, profileToQuery, profileFromQuery};
