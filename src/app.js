// ---------- state ----------
const LS_KEY = "bwd-atw-v1";
const ANALYTICS_TOKEN = ""; // Cloudflare Web Analytics token. Empty = no analytics at all.
let S = null; // state
let UI = {profOpen: !(window.matchMedia && matchMedia("(max-width: 980px)").matches), tab:"overview", open:{}, threatFilter:{scope:"applicable", outstanding:false, dom:"all", q:""}, ctrlAll:false};

// Example: a mid-maturity internal assistant. Some paths are already broken; others are not.
function exampleState(){
  const s = blankState();
  s.example = true;
  s.profile = {host:"api", autonomy:"approve", audience:"internal", feat:["data","rag","untrusted","tools","mcp","logging"]};
  const ev = (lvl, owner, evidence="") => ({lvl, owner, evidence});
  s.ctrl = {
    "ID-1": ev(3, "IAM", "Conditional access requires MFA for the assistant app; session lifetime 8h. Reviewed 2026-10."),
    "IN-3": ev(3, "AppSec", "System prompt reviewed 2026-10: no keys, tokens or access rules. Extraction test passed."),
    "OUT-2": ev(3, "Frontend", "Renderer strips remote images; CSP img-src self. Pen test 2026-09 confirmed no image exfil."),
    "GOV-3": ev(3, "Legal and procurement", "Zero data retention enabled in the provider console; EU region; DPA signed 2026-03."),
    "TL-1": ev(2, "Platform", "Per-agent tool allow-list in agents.yaml"),
    "ID-2": ev(2, "Platform", "One service principal per agent with scoped roles"),
    "TL-2": ev(2, "Platform", "OPA policy check in the tool gateway"),
    "TL-4": ev(2, "Platform"), "TL-5": ev(2, "Product"), "OUT-1": ev(2, "AppSec"), "DA-1": ev(2, "Data platform"),
    "GOV-1": ev(2, "Architecture"), "GOV-2": ev(2, "Platform"), "OBS-1": ev(2, "SRE"), "IN-4": ev(2, "Platform"),
    "ID-3": ev(1, "Platform", "Retrieval runs as the user; tool calls still use the agent identity"),
    "IN-1": ev(1, "AppSec", "Provenance tags on retrieved content; no quarantine yet"),
    "DA-4": ev(1, "Data protection"), "SC-1": ev(1, "Platform"), "SC-3": ev(1, "Platform", "Gateway in a container; two servers still bind 0.0.0.0"),
    "DA-6": ev(1, "SRE"), "OUT-4": ev(1, "Product")
  };
  s.det = {"DT-01":true, "DT-03":true, "DT-08":true, "DT-13":true};
  s.accept = {"T23":{owner:"CISO office", reason:"Vector store sits in the same restricted VPC as its sources; residual accepted until the Q2 re-architecture", expiry:"2027-06-30"}};
  s.findings = importAny(SAMPLE_OVERREACH, "overreach-sample.json");
  return s;
}
function load(){
  let st = null;
  try { const raw = localStorage.getItem(LS_KEY); if (raw) st = migrate(JSON.parse(raw)); } catch(e){}
  st = st || exampleState();
  const q = profileFromQuery(location.search);
  if (q){ st.profile = {host:q.host, autonomy:q.autonomy, audience:q.audience, feat:q.feat}; if (q.view) UI.tab = q.view; if (q.path) UI.mapPath = q.path; }
  return st;
}
function save(){ try { localStorage.setItem(LS_KEY, JSON.stringify(S)); } catch(e){} }
function shareLink(extra){
  const base = (location.protocol.startsWith("http") && !/claude|claudeusercontent/.test(location.hostname)) ? location.origin + location.pathname : "https://bogdanticu88.github.io/agent-threat-workbench/";
  return base + "?" + profileToQuery(S.profile, extra);
}
if (ANALYTICS_TOKEN){ document.addEventListener("DOMContentLoaded", () => { const n = document.getElementById("privacy-note"); if (n) n.textContent = "Your answers stay in this browser. The page counts visits with Cloudflare Web Analytics, which sets no cookies and never sees what you enter."; }); const sc = document.createElement("script"); sc.defer = true; sc.src = "https://static.cloudflareinsights.com/beacon.min.js"; sc.setAttribute("data-cf-beacon", JSON.stringify({token: ANALYTICS_TOKEN})); document.head.appendChild(sc); }

// ---------- helpers ----------
const $ = (q, r=document) => r.querySelector(q);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const famOf = id => id.split("-")[0];
const ctrlLevel = id => ctrlLevelOf(S, id);
// "TL-2, one of IN-1 / TL-3"
function missingText(m, html){
  const w = id => html ? `<span class="mono">${id}</span>` : id;
  return [...m.req.map(w), ...m.groups.map(g => "one of " + g.map(w).join(" / "))].join(", ");
}

// ---------- render: profile ----------
function seg(name, opts, cur){
  return `<div class="seg" role="radiogroup" aria-label="${name}">` + opts.map(([v, l]) =>
    `<button type="button" role="radio" aria-checked="${v===cur}" data-act="prof" data-k="${name}" data-v="${v}" class="${v===cur?"on":""}">${l}</button>`).join("") + `</div>`;
}
function renderProfile(M){
  const p = S.profile, F = new Set(p.feat);
  const summary = `${HOSTING.find(h=>h[0]===p.host)[1]} · ${AUTONOMY.find(h=>h[0]===p.autonomy)[1]} · ${AUDIENCE.find(h=>h[0]===p.audience)[1]} · ${p.feat.length} capabilities`;
  $("#profile").classList.toggle("collapsed", !UI.profOpen);
  if (!UI.profOpen){
    $("#profile").innerHTML = `<div class="prof-mini"><div><h2 class="side-h">Deployment profile</h2><p class="side-sum"><b>${M.app.length}</b> of ${THREATS.length} threats apply · ${esc(summary)}</p></div>
      <button type="button" class="prof-toggle" data-act="proftoggle" aria-expanded="false">Edit profile</button></div>`;
    return;
  }
  $("#profile").innerHTML = `
    <div class="prof-mini"><h2 class="side-h">Deployment profile</h2><button type="button" class="prof-toggle" data-act="proftoggle" aria-expanded="true">Done</button></div>
    <button type="button" class="prof-link" data-act="copylink">Copy link to this profile</button><span id="link-msg" class="small side-sum" role="status"></span>
    <p class="side-sum"><b>${M.app.length}</b> of ${THREATS.length} threats apply</p>
    <label class="lbl">Model hosting</label>${seg("host", HOSTING, p.host)}
    <label class="lbl">Autonomy</label>${seg("autonomy", AUTONOMY, p.autonomy)}
    <label class="lbl">Users</label>${seg("audience", AUDIENCE, p.audience)}
    <label class="lbl">Capabilities</label>
    <div class="feats">${FEATURES.map(([k, l, d]) => `
      <label class="feat" title="${esc(d)}"><input type="checkbox" id="f-${k}" data-act="feat" data-k="${k}" ${F.has(k)?"checked":""}><span>${l}</span></label>`).join("")}
    </div>`;
}

// ---------- pills ----------
const riskPill = r => `<span class="pill r-${r.toLowerCase()}">${r}</span>`;
const statPill = s => `<span class="pill s-${s.toLowerCase()}">${s}</span>`;
const gradePill = g => `<span class="pill g-${g}">${{proven:"Proven", simulated:"Simulated", reachable:"Reachable on spec", reported:"Reported"}[g]}</span>`;

// ---------- overview ----------
function renderOverview(M){
  const out = M.app.filter(t => M.threats[t.id].outstanding);
  const byB = b => out.filter(t => M.threats[t.id].risk === b).length;
  const st = s => M.count(x => x.status === s);
  const n = M.app.length || 1;
  const paths = M.paths.filter(p => p.applies);
  const openP = paths.filter(p => !p.blocked);
  const conflicts = M.app.filter(t => M.threats[t.id].conflict);
  const proven = M.app.filter(t => M.threats[t.id].proven).length;
  const reach = M.app.filter(t => M.threats[t.id].reach).length;
  const snap = S.snapshots[S.snapshots.length - 1];
  const bar = ["Verified","Mitigated","Partial","Accepted","Open"].map(s => { const c = st(s); return c ? `<span class="seg-bar s-${s.toLowerCase()}" style="flex:${c}" title="${s}: ${c}"></span>` : ""; }).join("");
  let delta = "";
  if (snap){
    const d = out.length - snap.outstanding, dm = (st("Mitigated")+st("Verified")) - snap.mitigated;
    delta = `<p class="muted small">Since snapshot "${esc(snap.label)}" (${esc(snap.date)}): outstanding ${d<=0?"":"+"}${d}, mitigated ${dm>=0?"+":""}${dm}.</p>`;
  }
  $("#v-overview").innerHTML = `
    ${S.example ? `<div class="banner">You are looking at an <b>example assessment</b>: a sample profile, a few control answers and real Overreach output from its reference API. <button type="button" class="link" data-act="clear">Start blank</button></div>` : ""}
    <p class="lede">${out.length} of ${M.app.length} applicable threats are outstanding${byB("Critical") ? `, <b class="t-crit">${byB("Critical")} critical</b>` : ""}. ${openP.length} of ${paths.length} attack paths are open end to end.</p>
    ${delta}
    <div class="tiles">
      <div class="tile"><div class="k">Outstanding</div><div class="v">${out.length}</div>
        <div class="bands">${["Critical","High","Medium","Low"].map(b => `<span>${riskPill(b)} ${byB(b)}</span>`).join("")}</div></div>
      <div class="tile"><div class="k">Assurance</div><div class="v">${st("Verified")}<small> verified</small></div>
        <div class="stack">${bar}</div>
        <div class="legend small">${["Verified","Mitigated","Partial","Accepted","Open"].map(s => `<span><i class="dot s-${s.toLowerCase()}"></i>${s} ${st(s)}</span>`).join("")}</div></div>
      <div class="tile"><div class="k">Attack paths</div><div class="v">${openP.length}<small> open</small></div>
        <div class="small muted">${paths.length - openP.length} broken, ${paths.filter(p => p.evidenceStages).length} with scanner evidence</div></div>
      <div class="tile ${conflicts.length ? "warn" : ""}"><div class="k">Findings</div><div class="v">${S.findings.length}</div>
        <div class="small muted">${proven} threats proven, ${reach} with any evidence${conflicts.length ? `<br><b class="t-crit">${conflicts.length} marked mitigated but proven exploitable</b>` : ""}</div></div>
    </div>
    <h3>Do these first</h3>
    <p class="muted small">Ranked by the outstanding risk each control would help close, plus a bonus for sitting on the easiest stage of an open attack path. It counts controls, not effort or cost. <a href="#report" data-act="tab" data-v="report">See the method and change the weights</a>. One control alone may not close a threat.</p>
    <ol class="lev">${M.leverage.slice(0, 7).map(l => `
      <li><button type="button" class="ctl-link" data-act="goctrl" data-id="${l.cid}"><span class="mono">${l.cid}</span> ${esc(CTRL[l.cid].t)}</button>
      <span class="small muted">P${CTRL[l.cid].p} · ${l.ts.length} threats (${l.ts.map(id => `<span class="mono">${id}</span>`).join(", ")})${l.pathBreaks ? ` · breaks ${l.pathBreaks} path${l.pathBreaks>1?"s":""}` : ""} · now: ${LEVELS[ctrlLevel(l.cid)]}</span></li>`).join("") || "<li>Nothing outstanding.</li>"}</ol>
    ${openP.length ? `<p class="nudge"><span>${openP.length} open attack path${openP.length>1?"s are":" is"} a claim until someone tests ${openP.length>1?"them":"it"}.</span> <a href="https://bitwisedefence.com/#contact">Bitwise Defence can test ${openP.length>1?"them":"it"} ↗</a></p>` : ""}
    <h3>Open attack paths</h3>
    <div class="mini-paths">${openP.map(p => `<button type="button" class="mini" data-act="tab" data-v="paths"><span class="mono">${p.id}</span> ${esc(p.t)}${p.evidenceStages ? ` <span class="pill g-reachable">${p.evidenceStages}/${p.stages.length} stages with evidence</span>` : ""}</button>`).join("") || `<p class="muted">None open.</p>`}</div>`;
}

// ---------- threats ----------
function renderThreats(M){
  const f = UI.threatFilter;
  let list = THREATS.filter(t => {
    const m = M.threats[t.id];
    if (f.scope === "applicable" && !m.applies) return false;
    if (f.scope === "na" && m.applies) return false;
    if (f.outstanding && !m.outstanding) return false;
    if (f.dom !== "all" && String(t.dom) !== f.dom) return false;
    if (f.q && !(t.id + " " + t.t + " " + t.s).toLowerCase().includes(f.q.toLowerCase())) return false;
    return true;
  });
  list.sort((a, b) => (M.threats[b.id].applies - M.threats[a.id].applies) || (M.threats[b.id].score - M.threats[a.id].score) || a.id.localeCompare(b.id));
  $("#v-threats").innerHTML = `
    <div class="filters">
      <label for="tf-scope">Show</label><select id="tf-scope" data-act="tf" data-k="scope">
        ${[["applicable","Applicable"],["na","Not applicable"],["all","All"]].map(([v,l]) => `<option value="${v}" ${f.scope===v?"selected":""}>${l}</option>`).join("")}</select>
      <label for="tf-dom">Domain</label><select id="tf-dom" data-act="tf" data-k="dom"><option value="all">All</option>${DOMAINS.map((d,i) => `<option value="${i}" ${f.dom===String(i)?"selected":""}>${d}</option>`).join("")}</select>
      <label class="chk"><input type="checkbox" id="tf-out" data-act="tf" data-k="outstanding" ${f.outstanding?"checked":""}> Outstanding only</label>
      <input type="search" id="tf-q" placeholder="Search threats" value="${esc(f.q)}" data-act="tfq" aria-label="Search threats">
      <span class="muted small">${list.length} shown</span>
    </div>
    <div class="tbl-wrap"><table class="tt">
      <thead><tr><th>ID</th><th>Threat</th><th>Risk</th><th>Status</th><th>Evidence</th><th>Detections</th></tr></thead>
      <tbody>${list.map(t => threatRow(t, M)).join("")}</tbody></table></div>`;
}
function threatRow(t, M){
  const m = M.threats[t.id], open = UI.open[t.id];
  const ev = m.proven ? gradePill("proven") : m.reach ? gradePill(m.findings[0].grade) : `<span class="muted small">None</span>`;
  return `<tr class="trow ${m.applies?"":"na"} ${m.conflict?"conflict":""}" data-act="toggle" data-id="${t.id}" tabindex="0" aria-expanded="${!!open}">
    <td class="mono">${t.id}</td><td>${esc(t.t)}<div class="small muted">${DOMAINS[t.dom]}</div></td>
    <td>${m.applies ? riskPill(m.risk) + `<div class="small muted mono">L${m.L} × I${m.I}</div>` : `<span class="muted small">n/a</span>`}</td>
    <td>${m.applies ? statPill(m.status) : ""}${m.conflict ? `<div class="small t-crit">Proven despite mitigation</div>` : ""}</td>
    <td>${ev}</td><td class="small">${t.d.length ? `${m.detDeployed}/${t.d.length} deployed` : `<span class="muted">None defined</span>`}</td></tr>
    ${open ? `<tr class="detail"><td colspan="6">${threatDetail(t, m)}</td></tr>` : ""}`;
}
function threatDetail(t, m){
  const maps = Object.entries(t.map || {}).map(([k, ids]) => ids.map(id => `<span class="tag" title="${esc(FRAMEWORKS[k].name)}">${esc(id)}${FRAMEWORKS[k].items[id] && k!=="mcp" ? ": " + esc(FRAMEWORKS[k].items[id]) : ""}</span>`).join("")).join("");
  const acc = S.accept[t.id];
  return `<div class="det">
    <p>${esc(t.s)}</p>
    ${!m.applies ? `<p class="muted small">Does not apply: needs ${[...(t.req||[]).map(k => FEATURES.find(f => f[0]===k)[1]), ...(t.any ? ["one of " + t.any.map(k => FEATURES.find(f => f[0]===k)[1]).join(", ")] : []), ...(t.when ? Object.entries(t.when).map(([k,v]) => k + ": " + v.join("/")) : [])].join(" + ")}.</p>` : ""}
    <p class="small muted">Base L${t.L} × I${t.I}. ${m.why.length ? m.why.join(". ") + "." : "No profile adjustment."} Controls never lower this rating; they change the status.</p>
    <div class="det-grid">
      <div>
        ${t.c.length ? `<h4>Required: all of these</h4>${t.c.map(cid => ctrlInline(cid, t.id)).join("")}` : ""}
        ${(t.alt || []).map((g, gi) => `<h4>Plus one of these</h4><div class="grp">${g.map(cid => ctrlInline(cid, t.id + "g" + gi)).join("")}</div>`).join("")}
        ${(t.opt || []).length ? `<h4>Also helps, not required</h4>${t.opt.map(cid => ctrlInline(cid, t.id + "o")).join("")}` : ""}
        <p class="small muted">${m.missing.count ? `Still needed: ${missingText(m.missing, true)}.` : "Every required control is in place."}</p></div>
      <div><h4>Detections</h4>
        ${t.d.length ? t.d.map(d => `<label class="chk"><input type="checkbox" id="d-${t.id}-${d}" data-act="det" data-id="${d}" ${S.det[d]?"checked":""}> <span class="mono">${d}</span> ${esc(DET[d][1])}</label>`).join("") : `<p class="muted small">No reliable detection. Rely on prevention.</p>`}
        <h4>Framework mapping</h4><div class="tags">${maps || `<span class="muted small">None</span>`}</div>
        ${t.cases ? `<h4>Public cases</h4><ul class="cases">${t.cases.map(c => `<li>${esc(c.t)} <a href="${esc(c.u)}" rel="noopener">Source ↗</a></li>`).join("")}</ul>` : ""}
        ${m.findings.length ? `<h4>Scanner findings</h4><ul class="cases">${m.findings.map(f => `<li>${gradePill(f.grade)} <span class="mono small">${esc(f.tool)}:${esc(f.id)}</span> ${esc(f.title)}</li>`).join("")}</ul>` : ""}
      </div>
    </div>
    ${m.applies && !(m.status==="Mitigated"||m.status==="Verified") ? `
    <details class="accept" ${acc?"open":""}><summary>${acc ? "Deviation accepted" : "Accept the residual risk"}</summary>
      <div class="acc-grid">
        <label for="a-o-${t.id}">Risk owner</label><input id="a-o-${t.id}" value="${esc(acc?.owner)}" data-act="acc" data-id="${t.id}" data-k="owner">
        <label for="a-e-${t.id}">Review by</label><input id="a-e-${t.id}" type="date" value="${esc(acc?.expiry)}" data-act="acc" data-id="${t.id}" data-k="expiry">
        <label for="a-r-${t.id}">Reason</label><textarea id="a-r-${t.id}" rows="2" data-act="acc" data-id="${t.id}" data-k="reason">${esc(acc?.reason)}</textarea>
      </div>
      <p class="small muted">Accepting records a decision. The risk stays ${m.risk} and the threat stays outstanding.${acc ? ` <button type="button" class="link" data-act="unaccept" data-id="${t.id}">Withdraw</button>` : ""}</p>
    </details>` : ""}
  </div>`;
}
function lvlSelect(cid, idp){
  const cur = S.ctrl[cid]?.lvl || 0;
  return `<select id="${idp}-${cid}" class="lvl l${ctrlLevel(cid)}" data-act="lvl" data-id="${cid}" aria-label="Maturity of ${cid}">${LEVELS.map((l, i) => `<option value="${i}" ${cur===i?"selected":""}>${l}</option>`).join("")}</select>`;
}
function ctrlInline(cid, tid){
  const c = CTRL[cid], warn = S.ctrl[cid]?.lvl === 3 && ctrlLevel(cid) < 3;
  return `<div class="ci"><div><span class="mono">${cid}</span> ${esc(c.t)} <span class="muted small">P${c.p}</span>${warn ? `<div class="small t-warn">Verified needs evidence: counted as Implemented</div>` : ""}</div>${lvlSelect(cid, "ti-" + tid)}</div>`;
}

// ---------- controls ----------
function renderControls(M){
  const fams = Object.keys(FAMILIES);
  const show = c => UI.ctrlAll || M.ctrlNeed[c.id];
  const appC = CONTROLS.filter(c => M.ctrlNeed[c.id]);
  const lvCount = i => appC.filter(c => ctrlLevel(c.id) === i).length;
  $("#v-controls").innerHTML = `
    <div class="filters"><span>${appC.length} controls apply. ${LEVELS.map((l,i) => `${l}: <b>${lvCount(i)}</b>`).join(" · ")}</span>
      <label class="chk"><input type="checkbox" id="c-all" data-act="ctrlall" ${UI.ctrlAll?"checked":""}> Show controls that do not apply</label></div>
    <p class="small muted">Implemented means in place and enforced. Verified means tested, with evidence written down. A threat counts as mitigated only when every control it needs is at least Implemented.</p>
    ${fams.map(f => { const cs = CONTROLS.filter(c => famOf(c.id) === f && show(c)); if (!cs.length) return ""; return `
      <h3>${FAMILIES[f]}</h3>
      ${cs.map(c => { const st = S.ctrl[c.id] || {}; const need = M.ctrlNeed[c.id] || []; const warn = st.lvl === 3 && ctrlLevel(c.id) < 3; return `
      <div class="crow ${need.length?"":"na"}" id="ctrl-${c.id}">
        <div class="ch"><div><span class="mono">${c.id}</span> <b>${esc(c.t)}</b> <span class="pill p${c.p}">P${c.p}</span>
          <div class="small muted">Needed by ${need.length ? need.map(id => `<span class="mono">${id}</span>`).join(", ") : "no applicable threat"}</div></div>
          ${lvlSelect(c.id, "cl")}</div>
        <details><summary class="small">Owner, evidence and how to test</summary>
          <div class="acc-grid">
            <label for="co-${c.id}">Owner</label><input id="co-${c.id}" value="${esc(st.owner)}" data-act="cfield" data-id="${c.id}" data-k="owner">
            <label for="ce-${c.id}">Evidence</label><textarea id="ce-${c.id}" rows="2" placeholder="${esc(c.ev)}" data-act="cfield" data-id="${c.id}" data-k="evidence">${esc(st.evidence)}</textarea>
          </div>
          <p class="small muted"><b>Good evidence:</b> ${esc(c.ev)}. <b>Test:</b> ${esc(c.test)}.</p>
        </details>
        ${warn ? `<div class="small t-warn">Verified needs evidence: counted as Implemented until you add it.</div>` : ""}
      </div>`; }).join("")}`; }).join("")}
    <h3>Detections</h3>
    <div class="dets">${DETECTIONS.map(([id, t, src]) => `<label class="chk det-row"><input type="checkbox" id="dd-${id}" data-act="det" data-id="${id}" ${S.det[id]?"checked":""}> <span class="mono">${id}</span> <span>${esc(t)}</span> <span class="muted small">${esc(src)}</span></label>`).join("")}</div>`;
}

// ---------- paths ----------
function renderPaths(M){
  const ps = M.paths;
  $("#v-paths").innerHTML = `
    <p class="small muted">A path applies when your profile has its prerequisites and every stage has at least one threat that applies. The attacker needs every stage, so breaking one stage breaks the path. A stage is broken only when every applicable threat in it is mitigated. Accepted risk does not break anything. Stages measure prevention only; detection coverage is shown separately, because an attack that is logged still succeeded.</p>
    ${ps.map(p => `
    <div class="path ${p.applies ? (p.blocked ? "blocked" : "open") : "na"}">
      <div class="ph"><span class="mono">${p.id}</span> <b>${esc(p.t)}</b>
        ${p.applies ? (p.blocked ? `<span class="pill s-mitigated">Broken</span>` : `<span class="pill s-open">Open</span>`) : `<span class="pill">Does not apply</span>`}
        ${p.applies ? `<span class="pill ${p.detOn.length ? "" : "s-open"}" title="Detections for threats on this path">Detection ${p.detOn.length}/${p.dets.length}</span>` : ""}
        ${p.evidenceStages ? `<span class="pill g-reachable">Scanner evidence on ${p.evidenceStages} of ${p.stages.length} stages</span>` : ""}</div>
      ${p.applies && p.dets.length ? `<p class="small muted">Would you see it? ${p.detOn.length ? `Deployed: ${p.detOn.map(d => `<span class="mono">${d}</span>`).join(", ")}. ` : "No detection deployed for this path. "}${p.dets.length - p.detOn.length ? `Not deployed: ${p.dets.filter(d => !S.det[d]).map(d => `<span class="mono">${d}</span>`).join(", ")}.` : ""}</p>` : ""}
      ${!p.gate ? `<p class="small muted">Needs ${esc(p.needs)}.</p>` : ""}${p.origin && p.gate ? `<p class="small muted">Starts from ${esc(p.origin)}.</p>` : ""}
      <ol class="stages">${p.stages.map((s, i) => `
        <li class="stage ${s.blocked?"b":""} ${p.cheapest===i?"cheap":""}">
          <div class="sn">${i+1}. ${esc(s.name)}</div>
          <div class="chips">${s.ids.map(id => { const m = M.threats[id]; return `<button type="button" class="chip ${m.applies ? "s-" + m.status.toLowerCase() : "na"}" data-act="gothreat" data-id="${id}" title="${esc(THR[id].t)}">${id}${m.reach ? " ●" : ""}</button>`; }).join("")}</div>
          ${p.cheapest===i ? `<div class="small"><b>Fewest missing controls:</b> ${[...s.missing.map(c => `<button type="button" class="ctl-link mono" data-act="goctrl" data-id="${c}" title="${esc(CTRL[c].t)}">${c}</button>`), ...s.missingGroups.map(g => "one of " + g.map(c => `<button type="button" class="ctl-link mono" data-act="goctrl" data-id="${c}" title="${esc(CTRL[c].t)}">${c}</button>`).join(" / "))].join(", ")}</div>` : ""}
        </li>`).join("")}</ol>
    </div>`).join("")}
    <p class="small muted">● marks a threat with scanner evidence.</p>`;
}

// ---------- findings ----------
function renderFindings(M){
  const unmapped = S.findings.filter(f => !f.threats.length).length;
  $("#v-findings").innerHTML = `
    <div class="import">
      <p>Import <b>Overreach</b> JSON (<span class="mono">overreach scan --json</span>) or SARIF (<span class="mono">--sarif</span>), any SARIF 2.1.0 file, or a list of findings as <span class="mono">{"findings":[{"title","threats":["T09"],"evidence":"validated"}]}</span>.</p>
      <div class="imp-row"><input type="file" id="imp-file" accept=".json,.sarif,application/json" data-act="impfile"><button type="button" data-act="impsample">Load Overreach sample</button></div>
      <textarea id="imp-text" rows="4" placeholder="Or paste JSON here" aria-label="Paste findings JSON"></textarea>
      <div class="imp-row"><button type="button" class="primary" data-act="imptext">Import pasted JSON</button><span id="imp-msg" class="small" role="status"></span></div>
      <p class="small muted">Evidence grades carry through. Overreach <i>hypothetical</i> means reachable on the API spec, <i>simulated</i> means replayed, <i>validated</i> means proven against the running system. Only validated findings mark a threat as proven, and a proven threat that is marked mitigated is flagged as a conflict. Mappings from Overreach outcomes or from an explicit <span class="mono">threats</span> list count straight away. Mappings guessed from rule names or tags are marked <i>suggested</i> and count only after you confirm them.</p>
    </div>
    <div class="filters"><span>${S.findings.length} findings${unmapped ? `, ${unmapped} not mapped to a threat` : ""}${S.findings.filter(f => f.confirmed === false).length ? `, ${S.findings.filter(f => f.confirmed === false).length} with suggested mappings to review` : ""}</span>${S.findings.length ? `<button type="button" class="link" data-act="clrfind">Remove all</button>` : ""}</div>
    <div class="tbl-wrap"><table class="tt"><thead><tr><th>Source</th><th>Finding</th><th>Evidence</th><th>Maps to</th><th></th></tr></thead><tbody>
    ${S.findings.map((f, i) => `<tr><td class="small"><span class="mono">${esc(f.tool)}</span><div class="muted">${esc(f.id)}</div></td>
      <td>${esc(f.title)}${f.impact ? ` <span class="muted small">impact ${esc(f.impact)}</span>` : ""}<div class="small mono muted wrap">${esc(f.detail)}</div>${f.notes.length ? `<div class="small muted">${f.notes.map(esc).join(" · ")}</div>` : ""}</td>
      <td>${gradePill(f.grade)}</td>
      <td class="mapcell">${f.confirmed === false ? `<span class="pill">Suggested</span> ` : ""}${f.threats.map(id => `<span class="chipx"><button type="button" class="chip ${M.threats[id].applies ? "s-" + M.threats[id].status.toLowerCase() : "na"}" data-act="gothreat" data-id="${id}" title="${esc(THR[id].t)}">${id}</button><button type="button" class="x" data-act="unmap" data-i="${i}" data-id="${id}" aria-label="Remove mapping to ${id}">×</button></span>`).join(" ") || `<span class="muted small">Unmapped</span>`}
        <div class="maprow"><select id="map-add-${i}" data-act="mapadd" data-i="${i}" aria-label="Map finding to a threat"><option value="">Add threat…</option>${THREATS.filter(t => !f.threats.includes(t.id)).map(t => `<option value="${t.id}">${t.id} ${esc(t.t.slice(0, 48))}</option>`).join("")}</select>
        ${f.confirmed === false && f.threats.length ? `<button type="button" class="link" data-act="mapok" data-i="${i}">Confirm mapping</button>` : ""}</div></td>
      <td><button type="button" class="link" data-act="delfind" data-i="${i}" aria-label="Remove finding">Remove</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted">No findings yet.</td></tr>`}
    </tbody></table></div>`;
}

// ---------- frameworks ----------
function renderFrameworks(M){
  $("#v-frameworks").innerHTML = `
    <p class="small muted">Coverage of each framework item by applicable threats in this profile. Use this to answer "where are we on the OWASP Agentic Top 10" in a review. The mappings are ours. They follow the OWASP LLM Top 10 2026 numbering (August 2026), the OWASP Agentic Top 10 2026 and ATLAS technique IDs, checked in November 2026. Check them against the current releases before you cite them in an audit.</p>
    ${Object.entries(FRAMEWORKS).map(([k, fw]) => `
      <h3>${esc(fw.name)} ${fw.url ? `<a class="small" href="${esc(fw.url)}" rel="noopener">Source ↗</a>` : ""}</h3>
      <div class="tbl-wrap"><table class="tt fw"><thead><tr><th>Item</th><th>Applicable threats</th><th>State</th></tr></thead><tbody>
      ${Object.entries(fw.items).map(([id, name]) => {
        const ts = THREATS.filter(t => (t.map?.[k] || []).includes(id));
        const app = ts.filter(t => M.threats[t.id].applies);
        const out = app.filter(t => M.threats[t.id].outstanding).length;
        const state = !app.length ? `<span class="muted small">Not in scope</span>` : out ? `<span class="pill s-open">${out} outstanding</span>` : `<span class="pill s-mitigated">Covered</span>`;
        return `<tr><td><span class="mono">${esc(id)}</span> ${k==="mcp" ? "" : esc(name)}</td><td>${ts.map(t => `<button type="button" class="chip ${M.threats[t.id].applies ? "s-" + M.threats[t.id].status.toLowerCase() : "na"}" data-act="gothreat" data-id="${t.id}" title="${esc(t.t)}">${t.id}</button>`).join(" ")}</td><td>${state}</td></tr>`;
      }).join("")}</tbody></table></div>`).join("")}`;
}

// ---------- report ----------
function renderReport(M){
  const acc = Object.entries(S.accept).filter(([id]) => M.threats[id]?.applies);
  $("#v-report").innerHTML = `
    <h3>Risk acceptance register</h3>
    <div class="tbl-wrap"><table class="tt"><thead><tr><th>Threat</th><th>Risk</th><th>Owner</th><th>Review by</th><th>Reason</th></tr></thead><tbody>
    ${acc.map(([id, a]) => { const expired = a.expiry && a.expiry < new Date().toISOString().slice(0,10); return `<tr><td><span class="mono">${id}</span> ${esc(THR[id].t)}</td><td>${riskPill(M.threats[id].risk)}</td><td>${esc(a.owner) || `<span class="t-warn small">No owner</span>`}</td><td class="${expired?"t-crit":""}">${esc(a.expiry) || `<span class="t-warn small">No date</span>`}${expired?" (overdue)":""}</td><td class="small">${esc(a.reason)}</td></tr>`; }).join("") || `<tr><td colspan="5" class="muted">No accepted deviations. Accept residual risk from a threat's detail view.</td></tr>`}
    </tbody></table></div>
    <h3>Export</h3>
    <p class="small muted">Exports open in a window with a Copy button. Paste into a file, a ticket import or a wiki page.</p>
    <div class="exp">
      <button type="button" data-act="exp" data-v="md">Review report (Markdown)</button>
      <button type="button" data-act="exp" data-v="csv">Threat register (CSV)</button>
      <button type="button" data-act="exp" data-v="tickets">Remediation tickets (CSV for Jira or ServiceNow)</button>
      <button type="button" data-act="exp" data-v="json">Assessment file (JSON)</button>
    </div>
    <h3>Load an assessment</h3>
    <div class="imp-row"><input type="file" id="load-file" accept=".json,application/json" data-act="loadfile"><span id="load-msg" class="small" role="status"></span></div>
    <h3>Snapshots</h3>
    <p class="small muted">A snapshot stores today's numbers in this browser so the overview can show what changed. They also travel in the assessment file.</p>
    <div class="imp-row"><input id="snap-label" placeholder="Label, e.g. Pre-release review" aria-label="Snapshot label"><button type="button" data-act="snap">Save snapshot</button></div>
    <ul class="snaps">${S.snapshots.slice().reverse().map(s => `<li><b>${esc(s.label)}</b> <span class="muted small">${esc(s.date)}</span> · ${s.outstanding} outstanding, ${s.mitigated} mitigated, ${s.openPaths} open paths</li>`).join("") || `<li class="muted">None yet.</li>`}</ul>
    ${methodHtml()}`;
}


// ---------- method: how the numbers are made, with editable weights ----------
function methodHtml(){
  const W = weightsOf(S), num = (k, v, step=1, min=0, max=5) => `<input type="number" class="wt" id="wt-${k.replace(".","-")}" data-act="wt" data-k="${k}" value="${v}" step="${step}" min="${min}" max="${max}">`;
  return `
    <h3 id="method">Method and weights</h3>
    <p class="small muted">Every number in this tool comes from the rules below. They are judgement, not measurement. Change the weights to match your own risk method; the defaults are restored with one click.</p>
    <div class="method">
      <div><h4>Risk rating</h4>
        <p class="small">Each threat has a base likelihood and impact from 1 to 5. Score = likelihood × impact. Your profile adjusts them:</p>
        <ul class="small">
          <li>Agent acts on its own: likelihood of action threats + ${num("act", W.act)} (minus the same when it only suggests)</li>
          <li>Users outside the company: likelihood of exposure threats + ${num("exposed", W.exposed)}</li>
          <li>Sensitive data in scope: impact of data threats + ${num("data", W.data)}</li>
          <li>Multi-tenant service: likelihood of tenant threats + ${num("mt", W.mt)}</li>
        </ul>
        <p class="small">Bands: Critical at ${num("band.0", W.bands[0], 1, 1, 25)} or more, High at ${num("band.1", W.bands[1], 1, 1, 25)}, Medium at ${num("band.2", W.bands[2], 1, 1, 25)}, otherwise Low. Controls never change the rating.</p></div>
      <div><h4>Status</h4>
        <p class="small">A threat is <b>Mitigated</b> when every required control is at least Implemented and each group of alternatives has at least one. <b>Verified</b> needs the same at Verified, and Verified only counts with evidence written down. <b>Partial</b> means some work exists. <b>Accepted</b> records a decision; the threat stays outstanding.</p>
        <h4>Attack paths</h4>
        <p class="small">A path applies when the profile meets its prerequisites and every stage has an applicable threat. A stage is broken when all its applicable threats are mitigated; one broken stage breaks the path. Detection is reported beside the path and never breaks it.</p></div>
      <div><h4>"Do these first" ranking</h4>
        <p class="small">For each control not yet Implemented: add the weight of every outstanding threat that requires it (Critical ${num("rank.Critical", W.rank.Critical, 0.5, 0, 10)}, High ${num("rank.High", W.rank.High, 0.5, 0, 10)}, Medium ${num("rank.Medium", W.rank.Medium, 0.5, 0, 10)}, Low ${num("rank.Low", W.rank.Low, 0.5, 0, 10)}). Where it is one of several alternatives it earns ${num("altShare", W.altShare, 0.1, 0, 1)} of that weight. Add ${num("path", W.path, 0.5, 0, 10)} for each open path where it sits on the stage with the fewest missing controls.
        <label class="chk"><input type="checkbox" id="wt-prio" data-act="wt" data-k="prio" ${W.prio ? "checked" : ""}> Break ties in favour of P1 controls</label></p>
        <p><button type="button" data-act="wreset">Restore default weights</button></p></div>
    </div>`;
}

// ---------- exports ----------
const csvq = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
function exportText(kind, M){
  const p = S.profile, today = new Date().toISOString().slice(0,10);
  const profTxt = `${HOSTING.find(h=>h[0]===p.host)[1]}; ${AUTONOMY.find(h=>h[0]===p.autonomy)[1]}; ${AUDIENCE.find(h=>h[0]===p.audience)[1]}; ${p.feat.map(k => FEATURES.find(f=>f[0]===k)[1]).join(", ")}`;
  const out = M.app.filter(t => M.threats[t.id].outstanding).sort((a,b) => M.threats[b.id].score - M.threats[a.id].score);
  if (kind === "json") return JSON.stringify({schema:"bwd-atw/0.2", saved:new Date().toISOString(), state:S}, null, 2);
  if (kind === "csv"){
    const rows = [["ID","Threat","Domain","Applies","Likelihood","Impact","Risk","Status","Controls missing","Evidence","OWASP LLM","OWASP Agentic","ATLAS"]];
    THREATS.forEach(t => { const m = M.threats[t.id]; rows.push([t.id, t.t, DOMAINS[t.dom], m.applies?"yes":"no", m.L, m.I, m.risk, m.applies?m.status:"", m.applies ? missingText(m.missing) : "", m.proven?"proven":m.reach?"reachable":"", (t.map?.llm||[]).join(" "), (t.map?.asi||[]).join(" "), (t.map?.atlas||[]).join(" ")]); });
    return rows.map(r => r.map(csvq).join(",")).join("\n");
  }
  if (kind === "tickets"){
    const rows = [["Summary","Priority","Description","Labels","Owner"]];
    M.leverage.forEach(l => { const c = CTRL[l.cid]; rows.push([`[AI agent] ${l.cid}: ${c.t}`, c.p===1?"High":c.p===2?"Medium":"Low",
      `Current state: ${LEVELS[ctrlLevel(l.cid)]}. Helps close: ${l.ts.map(id => id + " " + THR[id].t + " (" + M.threats[id].risk + ")").join("; ")}.${l.pathBreaks ? " Breaks " + l.pathBreaks + " open attack path(s)." : ""} Done when: ${c.ev}. Verify by: ${c.test}.`,
      "ai-security agent-threat-model " + famOf(l.cid).toLowerCase(), S.ctrl[l.cid]?.owner || ""]); });
    return rows.map(r => r.map(csvq).join(",")).join("\n");
  }
  // markdown
  const L = [];
  L.push(`# Agent threat model review`, ``, `Date: ${today}  `, `Profile: ${profTxt}`, ``);
  L.push(`## Summary`, ``, `${out.length} of ${M.app.length} applicable threats are outstanding: ${["Critical","High","Medium","Low"].map(b => out.filter(t => M.threats[t.id].risk===b).length + " " + b).join(", ")}. ${M.count(x=>x.status==="Verified")} verified, ${M.count(x=>x.status==="Mitigated")} mitigated, ${M.count(x=>x.status==="Accepted")} accepted. ${M.paths.filter(p=>p.applies&&!p.blocked).length} of ${M.paths.filter(p=>p.applies).length} attack paths are open.`, ``);
  const conf = M.app.filter(t => M.threats[t.id].conflict);
  if (conf.length){ L.push(`**Conflicts:** ${conf.map(t => t.id).join(", ")} are marked mitigated but a validated finding shows them exploitable.`, ``); }
  L.push(`## Priority controls`, ``); M.leverage.slice(0, 10).forEach((l, i) => L.push(`${i+1}. **${l.cid}** ${CTRL[l.cid].t} (P${CTRL[l.cid].p}, now ${LEVELS[ctrlLevel(l.cid)]}). Helps close ${l.ts.join(", ")}.`)); L.push(``);
  L.push(`## Outstanding threats`, ``, `| ID | Threat | Risk | Status | Missing controls | Evidence |`, `|---|---|---|---|---|---|`);
  out.forEach(t => { const m = M.threats[t.id]; L.push(`| ${t.id} | ${t.t} | ${m.risk} | ${m.status} | ${missingText(m.missing)} | ${m.proven?"Proven":m.reach?"Reachable":""} |`); }); L.push(``);
  L.push(`## Attack paths`, ``); M.paths.filter(p=>p.applies).forEach(p => L.push(`- **${p.id} ${p.t}**: ${p.blocked ? "broken" : "open"}, detection ${p.detOn.length}/${p.dets.length}${!p.blocked && p.cheapest!==null ? `. Fewest missing controls at stage ${p.cheapest+1} (${p.stages[p.cheapest].name}): ${missingText({req:p.stages[p.cheapest].missing, groups:p.stages[p.cheapest].missingGroups})}` : ""}.`)); L.push(``);
  if (S.findings.length){ L.push(`## Scanner findings`, ``); S.findings.forEach(f => L.push(`- ${f.tool}:${f.id} ${f.title} (${f.grade}) maps to ${f.threats.join(", ") || "nothing"}`)); L.push(``); }
  const acc = Object.entries(S.accept).filter(([id]) => M.threats[id]?.applies);
  if (acc.length){ L.push(`## Accepted risk`, ``, `| Threat | Risk | Owner | Review by | Reason |`, `|---|---|---|---|---|`); acc.forEach(([id,a]) => L.push(`| ${id} ${THR[id].t} | ${M.threats[id].risk} | ${a.owner||""} | ${a.expiry||""} | ${(a.reason||"").replace(/\|/g,"/")} |`)); L.push(``); }
  L.push(`---`, `Prepared with the Bitwise Defence Agent Threat Workbench 0.3. Ratings are an assessment aid, not advice for a specific system.  `, `Independent testing of agent boundaries and attack paths: contact@bitwisedefence.com, https://bitwisedefence.com`);
  return L.join("\n");
}
function openModal(title, text){
  $("#m-title").textContent = title; $("#m-text").value = text; $("#m-msg").textContent = "";
  $("#modal").hidden = false; $("#m-text").focus(); $("#m-text").select();
}

// ---------- render all ----------
let M = null;
function render(){
  M = compute(S);
  renderProfile(M);
  document.querySelectorAll(".tabs button").forEach(b => { const on = b.dataset.v === UI.tab; b.setAttribute("aria-selected", on); b.classList.toggle("on", on); });
  document.querySelectorAll(".view").forEach(v => v.hidden = v.id !== "v-" + UI.tab);
  ({overview:renderOverview, threats:renderThreats, controls:renderControls, paths:renderPaths, map:renderMap, findings:renderFindings, frameworks:renderFrameworks, report:renderReport})[UI.tab](M);
  const out = M.app.filter(t => M.threats[t.id].outstanding).length;
  $("#hdr-count").textContent = `${out} outstanding · ${M.count(x => x.status === "Verified")} verified`;
  save();
}
function setTab(t){ UI.tab = t; try { history.replaceState(null, "", "#" + t); } catch(e){ location.hash = t; } render(); window.scrollTo({top:0}); }

// ---------- events ----------
document.addEventListener("click", e => {
  const el = e.target.closest("[data-act]"); if (!el) return;
  const a = el.dataset.act;
  if (a === "proftoggle"){ UI.profOpen = !UI.profOpen; render(); }
  else if (a === "prof"){ S.profile[el.dataset.k] = el.dataset.v; render(); }
  else if (a === "tab"){ setTab(el.dataset.v); }
  else if (a === "toggle"){ if (e.target.closest("select,input,textarea,button,a,label")) return; UI.open[el.dataset.id] = !UI.open[el.dataset.id]; render(); }
  else if (a === "gothreat"){ UI.open[el.dataset.id] = true; UI.threatFilter.scope = M.threats[el.dataset.id].applies ? "applicable" : "all"; UI.threatFilter.q = ""; UI.threatFilter.dom = "all"; UI.threatFilter.outstanding = false; setTab("threats"); const r = document.querySelector(`[data-id="${el.dataset.id}"].trow`); if (r) r.scrollIntoView({block:"center"}); }
  else if (a === "goctrl"){ setTab("controls"); const r = $("#ctrl-" + el.dataset.id); if (r){ r.scrollIntoView({block:"center"}); r.classList.add("flash"); setTimeout(() => r.classList.remove("flash"), 1500); } }
  else if (a === "clear"){ S = blankState(); UI.open = {}; render(); }
  else if (a === "example"){ S = exampleState(); render(); }
  else if (a === "unaccept"){ delete S.accept[el.dataset.id]; render(); }
  else if (a === "impsample"){ addFindings(importAny(SAMPLE_OVERREACH, "overreach-sample.json")); }
  else if (a === "imptext"){ try { addFindings(importAny(JSON.parse($("#imp-text").value), "pasted")); } catch(err){ $("#imp-msg").textContent = "Could not import: " + err.message; } }
  else if (a === "delfind"){ S.findings.splice(+el.dataset.i, 1); render(); }
  else if (a === "unmap"){ const f = S.findings[+el.dataset.i]; f.threats = f.threats.filter(x => x !== el.dataset.id); render(); }
  else if (a === "mapok"){ S.findings[+el.dataset.i].confirmed = true; render(); }
  else if (a === "copylink"){ const url = shareLink(); const done = m => { const s = $("#link-msg"); if (s) s.textContent = m; };
    (navigator.clipboard ? navigator.clipboard.writeText(url) : Promise.reject()).then(() => done("Link copied."), () => openModal("Link to this profile", url)); }
  else if (a === "wreset"){ S.weights = null; render(); }
  else if (a === "clrfind"){ S.findings = []; render(); }
  else if (a === "exp"){ const names = {md:"Review report (Markdown)", csv:"Threat register (CSV)", tickets:"Remediation tickets (CSV)", json:"Assessment file (JSON)"}; openModal(names[el.dataset.v], exportText(el.dataset.v, M)); }
  else if (a === "snap"){ const lbl = $("#snap-label").value.trim() || "Snapshot " + (S.snapshots.length + 1);
    S.snapshots.push({label:lbl, date:new Date().toISOString().slice(0,10), outstanding:M.app.filter(t => M.threats[t.id].outstanding).length, mitigated:M.count(x => x.status==="Mitigated"||x.status==="Verified"), openPaths:M.paths.filter(p => p.applies && !p.blocked).length}); render(); }
  else if (a === "mclose"){ $("#modal").hidden = true; }
  else if (a === "mcopy"){ const t = $("#m-text"); t.select(); navigator.clipboard.writeText(t.value).then(() => $("#m-msg").textContent = "Copied.", () => { document.execCommand && document.execCommand("copy"); $("#m-msg").textContent = "Selected. Press Ctrl+C or Cmd+C if it did not copy."; }); }
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && !$("#modal").hidden) $("#modal").hidden = true;
  if ((e.key === "Enter" || e.key === " ") && e.target.matches("tr.trow")){ e.preventDefault(); UI.open[e.target.dataset.id] = !UI.open[e.target.dataset.id]; render(); const r = document.querySelector(`tr.trow[data-id="${e.target.dataset.id}"]`); r && r.focus(); }
});
document.addEventListener("change", e => {
  const el = e.target, a = el.dataset.act; if (!a) return;
  if (a === "feat"){ const f = new Set(S.profile.feat); el.checked ? f.add(el.dataset.k) : f.delete(el.dataset.k); S.profile.feat = FEATURES.map(x => x[0]).filter(k => f.has(k)); render(); }
  else if (a === "mapadd"){ if (el.value){ const f = S.findings[+el.dataset.i]; f.threats.push(el.value); f.confirmed = true; render(); } }
  else if (a === "wt"){ const W = S.weights ||= {}; const k = el.dataset.k, v = Number(el.value);
    if (k.startsWith("rank.")){ (W.rank ||= {})[k.slice(5)] = v; } else if (k.startsWith("band.")){ const b = (W.bands ||= DEFAULT_WEIGHTS.bands.slice()); b[+k.slice(5)] = v; } else if (k === "prio"){ W.prio = el.checked; } else W[k] = v; render(); }
  else if (a === "lvl"){ const c = S.ctrl[el.dataset.id] ||= {}; c.lvl = +el.value; render(); }
  else if (a === "det"){ S.det[el.dataset.id] = el.checked; render(); }
  else if (a === "tf"){ UI.threatFilter[el.dataset.k] = el.type === "checkbox" ? el.checked : el.value; render(); }
  else if (a === "ctrlall"){ UI.ctrlAll = el.checked; render(); }
  else if (a === "cfield"){ const c = S.ctrl[el.dataset.id] ||= {lvl:0}; c[el.dataset.k] = el.value; render(); }
  else if (a === "acc"){ const x = S.accept[el.dataset.id] ||= {}; x[el.dataset.k] = el.value; if (!x.owner && !x.reason && !x.expiry) delete S.accept[el.dataset.id]; render(); }
  else if (a === "impfile" || a === "loadfile"){ const file = el.files[0]; if (!file) return; file.text().then(txt => {
      try { const obj = JSON.parse(txt);
        if (a === "loadfile" || /^bwd-atw\//.test(obj.schema || "")){ const st = migrate(obj.state); if (!st) throw new Error("Not a workbench assessment file."); S = st; S.example = false; render(); }
        else addFindings(importAny(obj, file.name));
      } catch(err){ const m = $(a === "loadfile" ? "#load-msg" : "#imp-msg"); if (m) m.textContent = "Could not load: " + err.message; } }); }
});
document.addEventListener("input", e => {
  if (e.target.dataset.act === "tfq"){ UI.threatFilter.q = e.target.value; const pos = e.target.selectionStart; render(); const q = $("#tf-q"); q.focus(); q.setSelectionRange(pos, pos); }
});
function addFindings(list){
  const keys = new Set(S.findings.map(f => f.key));
  const fresh = list.filter(f => !keys.has(f.key));
  S.findings.push(...fresh); S.example = S.example && true; render();
  const m = $("#imp-msg"); if (m) m.textContent = `Imported ${fresh.length} finding${fresh.length===1?"":"s"}${list.length - fresh.length ? `, skipped ${list.length - fresh.length} already loaded` : ""}.`;
}
window.addEventListener("hashchange", () => { const h = location.hash.slice(1); if (h && h !== UI.tab && document.getElementById("v-" + h)) { UI.tab = h; render(); } });

// ---------- boot ----------
// Deferred so every script part (including the 3D map) is defined before the first render.
function boot(){
  S = load();
  const h = location.hash.slice(1); if (h && document.getElementById("v-" + h)) UI.tab = h;
  render();
}
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else setTimeout(boot, 0);
