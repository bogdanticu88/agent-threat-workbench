// ---------- 3D map ----------
// Isometric board: trust zones left to right, components as blocks, threats stacked as columns,
// flows as dashed lines with moving packets, attack paths replayed as a token stopped by gates.
const MAP_COLORS = {paper:0xeeeae1, paper2:0xe3e5d9, surface:0xf5f4e8, ink:0x20251f, line:0xb9bdb0, muted:0x656b60, acid:0xd1ee6b, olive:0x667b40,
  crit:0x9b2318, high:0xa8501a, med:0xc9a646, low:0x8a917f, acc:0x4b4f6b};
const ZONES = [["out","Outside"],["users","Users and clients"],["app","Application and orchestration"],["data","Data and tools"],["model","Model providers"]];
const COMPONENTS = [
  // id, label, zone, show(profile, featureSet)
  ["atk","Attacker","out", () => true],
  ["ext","Email, web pages, files","out", (p,F) => F.has("untrusted") || F.has("browser")],
  ["repo","Repos and issues","out", (p,F) => F.has("coding")],
  ["reg","Registries: MCP, plugins, models","out", (p,F) => F.has("mcp") || F.has("plugins") || F.has("selfhost")],
  ["user","Users","users", () => true],
  ["client","Chat client","users", () => true],
  ["ws","Developer workstation","users", (p,F) => F.has("coding")],
  ["app","AI application","app", () => true],
  ["policy","Guardrails and policy","app", () => true],
  ["orch","Agent orchestrator","app", (p,F) => F.has("tools")],
  ["approval","Approval step","app", (p) => p.autonomy === "approve"],
  ["agents","Other agents","app", (p,F) => F.has("multi")],
  ["docs","Document sources","data", (p,F) => F.has("rag")],
  ["vec","Vector store","data", (p,F) => F.has("rag")],
  ["mem","Memory","data", (p,F) => F.has("memory")],
  ["tools","Tools and APIs","data", (p,F) => F.has("tools")],
  ["mcp","MCP servers","data", (p,F) => F.has("mcp")],
  ["sandbox","Code sandbox","data", (p,F) => F.has("code")],
  ["browser","Browser or desktop","data", (p,F) => F.has("browser")],
  ["logs","Prompt and trace logs","data", (p,F) => F.has("logging")],
  ["llm","LLM","model", () => true]
];
const FLOWS = [["user","client"],["client","app"],["app","llm"],["app","policy"],["app","orch"],["orch","tools"],["orch","mcp"],["orch","approval"],["orch","sandbox"],["orch","agents"],["orch","browser"],
  ["ext","app"],["docs","vec"],["vec","app"],["app","mem"],["app","logs"],["reg","mcp"],["repo","ws"],["ws","llm"],["ws","orch"]];
const ANCHOR = {T01:"client",T02:"ext",T03:"tools",T04:"mcp",T05:"reg",T06:"reg",T07:"orch",T08:"client",T09:"orch",T10:"mcp",T11:"mcp",T12:"mcp",T13:"client",T14:"tools",
  T15:"orch",T16:"orch",T17:"approval",T18:"app",T19:"sandbox",T20:"ws",T21:"vec",T22:"docs",T23:"vec",T24:"mem",T25:"mem",T26:"app",T27:"logs",T28:"llm",T29:"llm",T30:"llm",
  T31:"client",T32:"llm",T33:"agents",T34:"agents",T35:"policy",T36:"app",T37:"logs",T38:"orch",T39:"llm",T40:"browser",T41:"user",T42:"orch",T43:"orch"};
const RISK_H = {Critical:4, High:3, Medium:2, Low:1};

const MAPS = {built:false, az:Math.PI*0.25, el:0.62, zoom:1, path:"", sel:null, hover:null, t0:0, raf:0, dirty:true, paused:false};
const reduceMotion = () => window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

function statusColor(m){
  if (!m.applies) return MAP_COLORS.line;
  return {Contradicted:MAP_COLORS.crit, Verified:MAP_COLORS.ink, Mitigated:MAP_COLORS.olive, Partial:MAP_COLORS.med, Accepted:MAP_COLORS.acc, Open:({Critical:MAP_COLORS.crit, High:MAP_COLORS.crit, Medium:MAP_COLORS.high, Low:MAP_COLORS.low})[m.risk]}[m.status];
}

function mapShell(){
  const v = $("#v-map");
  v.innerHTML = `
    <div class="map-bar">
      <label for="map-path">Replay an attack path</label>
      <select id="map-path" data-act="mappath"></select>
      <button type="button" data-act="mapplay" id="map-play">Pause</button>
      <button type="button" data-act="mapreset">Reset view</button>
      <button type="button" data-act="maptop">Top view</button>
      <span class="small muted map-hint">Drag to rotate, scroll or pinch to zoom, arrow keys and + / - on the map.</span>
    </div>
    <div class="map-wrap">
      <div id="map-stage" tabindex="0" aria-label="3D map of the deployment. Arrow keys rotate, plus and minus zoom. The outline below lists the same content."></div>
      <div id="map-labels" aria-hidden="true"></div>
      <div id="map-tip" hidden></div>
      <aside id="map-panel"></aside>
    </div>
    <div class="map-legend small">
      <span><i style="background:#9b2318"></i>Open</span><span><i style="background:#c9a646"></i>Partial</span><span><i style="background:#667b40"></i>Mitigated</span><span><i style="background:#20251f;outline:2px solid #d1ee6b"></i>Verified</span><span><i style="background:#4b4f6b"></i>Accepted</span>
      <span>Column height = risk</span><span><i class="ring"></i>Scanner evidence</span><span><i style="background:#d1ee6b"></i>Gate: stage broken</span>
    </div>
    <details class="map-outline"><summary class="small">Text outline of the map</summary><div id="map-outline"></div></details>`;
}

function mapInit(){
  if (MAPS.built) return true;
  if (!window.THREE){ $("#v-map").innerHTML = `<p class="muted">The 3D map needs WebGL and the three.js library, which did not load. The Threats and Attack paths tabs show the same information.</p>`; return false; }
  mapShell();
  const host = $("#map-stage");
  let renderer;
  try { renderer = new THREE.WebGLRenderer({antialias:true, alpha:false}); } catch(e){ host.innerHTML = `<p class="muted" style="padding:20px">WebGL is not available in this browser. The Threats and Attack paths tabs show the same information.</p>`; return false; }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(MAP_COLORS.paper);
  host.appendChild(renderer.domElement);
  const scene = new THREE.Scene();
  const camera = new THREE.OrthographicCamera(-10, 10, 10, -10, -200, 400);
  scene.add(new THREE.HemisphereLight(0xffffff, 0xb9bdb0, 0.85));
  const sun = new THREE.DirectionalLight(0xffffff, 0.55); sun.position.set(-8, 20, 12); scene.add(sun);
  Object.assign(MAPS, {renderer, scene, camera, host, built:true, root:null, ray:new THREE.Raycaster(), ptr:new THREE.Vector2()});
  const ro = new ResizeObserver(() => mapResize()); ro.observe(host); MAPS.ro = ro;
  // pointer controls
  let down = null;
  const cv = renderer.domElement;
  cv.addEventListener("pointerdown", e => { down = {x:e.clientX, y:e.clientY, az:MAPS.az, el:MAPS.el, moved:false}; cv.setPointerCapture(e.pointerId); });
  cv.addEventListener("pointermove", e => {
    if (down){ const dx = e.clientX - down.x, dy = e.clientY - down.y; if (Math.abs(dx) + Math.abs(dy) > 4) down.moved = true;
      MAPS.az = down.az - dx * 0.008; MAPS.el = Math.max(0.15, Math.min(1.45, down.el + dy * 0.006)); return; }
    mapPick(e, false);
  });
  cv.addEventListener("pointerup", e => { if (down && !down.moved) mapPick(e, true); down = null; });
  cv.addEventListener("pointerleave", () => { MAPS.hover = null; $("#map-tip").hidden = true; });
  cv.addEventListener("wheel", e => { e.preventDefault(); MAPS.zoom = Math.max(0.5, Math.min(3, MAPS.zoom * (e.deltaY > 0 ? 0.9 : 1.1))); }, {passive:false});
  host.addEventListener("keydown", e => {
    const k = e.key; let used = true;
    if (k === "ArrowLeft") MAPS.az += 0.12; else if (k === "ArrowRight") MAPS.az -= 0.12;
    else if (k === "ArrowUp") MAPS.el = Math.min(1.45, MAPS.el + 0.08); else if (k === "ArrowDown") MAPS.el = Math.max(0.15, MAPS.el - 0.08);
    else if (k === "+" || k === "=") MAPS.zoom = Math.min(3, MAPS.zoom * 1.1); else if (k === "-") MAPS.zoom = Math.max(0.5, MAPS.zoom / 1.1);
    else used = false;
    if (used) e.preventDefault();
  });
  // pinch
  const touches = new Map(); let pinch0 = 0, zoom0 = 1;
  cv.addEventListener("touchstart", e => { if (e.touches.length === 2){ pinch0 = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY); zoom0 = MAPS.zoom; } }, {passive:true});
  cv.addEventListener("touchmove", e => { if (e.touches.length === 2 && pinch0){ const d = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY); MAPS.zoom = Math.max(0.5, Math.min(3, zoom0 * d / pinch0)); } }, {passive:true});
  return true;
}

function mapResize(){
  if (!MAPS.built) return;
  const w = MAPS.host.clientWidth, h = MAPS.host.clientHeight;
  if (!w || !h) return;
  MAPS.renderer.setSize(w, h, false);
  MAPS.w = w; MAPS.h = h;
}

function box(w, h, d, color, opts={}){
  const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), new THREE.MeshLambertMaterial({color, transparent:!!opts.opacity, opacity:opts.opacity ?? 1}));
  if (opts.edges){ const e = new THREE.LineSegments(new THREE.EdgesGeometry(m.geometry), new THREE.LineBasicMaterial({color:opts.edges})); m.add(e); }
  return m;
}

function mapBuild(M){
  const p = S.profile, F = new Set(p.feat);
  if (MAPS.root){ MAPS.scene.remove(MAPS.root); MAPS.root.traverse(o => { o.geometry && o.geometry.dispose(); if (o.material) (Array.isArray(o.material) ? o.material : [o.material]).forEach(m => m.dispose()); }); }
  const root = new THREE.Group(); MAPS.root = root; MAPS.scene.add(root);
  const comps = COMPONENTS.filter(c => c[3](p, F));
  const ZW = 5.4, GAP = 0.9, CZ = 2.7;
  const zoneX = {}; ZONES.forEach(([z], i) => zoneX[z] = (i - 2) * (ZW + GAP));
  const byZone = {}; comps.forEach(c => (byZone[c[2]] ||= []).push(c));
  const maxN = Math.max(...Object.values(byZone).map(a => a.length));
  const depth = maxN * CZ + 1.6;
  // ground
  const ground = new THREE.Mesh(new THREE.PlaneGeometry(5 * (ZW + GAP) + 6, depth + 6), new THREE.MeshLambertMaterial({color:MAP_COLORS.paper}));
  ground.rotation.x = -Math.PI / 2; ground.position.y = -0.02; root.add(ground);
  const grid = new THREE.GridHelper(Math.max(5 * (ZW + GAP) + 6, depth + 6), 40, MAP_COLORS.line, MAP_COLORS.line);
  grid.material.transparent = true; grid.material.opacity = 0.35; root.add(grid);
  MAPS.labels = []; MAPS.pick = []; MAPS.pos = {}; MAPS.pulses = []; MAPS.packets = [];
  ZONES.forEach(([z, name]) => {
    const slab = box(ZW, 0.08, depth, z === "out" ? 0xe4ddd0 : MAP_COLORS.paper2, {edges: z === "app" ? MAP_COLORS.ink : MAP_COLORS.line});
    slab.position.set(zoneX[z], 0.04, 0); root.add(slab);
    MAPS.labels.push({pos:new THREE.Vector3(zoneX[z], 0.1, -depth / 2 + 0.3), html:`<span class="ml-zone">${esc(name)}</span>`, cls:"mlz"});
  });
  comps.forEach(c => {
    const list = byZone[c[2]], i = list.indexOf(c), n = list.length;
    const x = zoneX[c[2]], z = (i - (n - 1) / 2) * CZ;
    const isAtk = c[0] === "atk";
    const b = box(3.4, 0.55, 1.5, isAtk ? MAP_COLORS.crit : MAP_COLORS.ink, {edges: isAtk ? 0x5e140e : 0x000000});
    b.position.set(x, 0.36, z); root.add(b);
    const top = box(3.2, 0.02, 1.3, isAtk ? 0xb8483d : 0x2b3129); top.position.set(x, 0.645, z); root.add(top);
    MAPS.pos[c[0]] = new THREE.Vector3(x, 0.65, z);
    MAPS.labels.push({pos:new THREE.Vector3(x, 0.66, z + 0.95), html:`<span class="ml-comp">${esc(c[1])}</span>`, cls:"mlc", id:c[0]});
  });
  // flows
  FLOWS.forEach(([a, b]) => {
    if (!MAPS.pos[a] || !MAPS.pos[b]) return;
    const A = MAPS.pos[a].clone().setY(0.3), B = MAPS.pos[b].clone().setY(0.3);
    const g = new THREE.BufferGeometry().setFromPoints([A, B]);
    const l = new THREE.Line(g, new THREE.LineDashedMaterial({color:MAP_COLORS.muted, dashSize:0.25, gapSize:0.18})); l.computeLineDistances(); root.add(l);
    const pk = box(0.16, 0.16, 0.16, MAP_COLORS.ink); pk.position.copy(A); root.add(pk);
    MAPS.packets.push({m:pk, A, B, off:Math.random()});
  });
  // threat columns
  const stacks = {};
  M.app.forEach(t => {
    let a = ANCHOR[t.id]; if (!MAPS.pos[a]) a = "app";
    (stacks[a] ||= []).push(t);
  });
  Object.entries(stacks).forEach(([a, ts]) => {
    ts.sort((x, y) => M.threats[y.id].score - M.threats[x.id].score);
    const base = MAPS.pos[a];
    ts.forEach((t, i) => {
      const m = M.threats[t.id], h = RISK_H[m.risk] * 0.42;
      const col = i % 6, row = Math.floor(i / 6);
      const x = base.x - 1.35 + col * 0.54, z = base.z - 0.32 + row * 0.6;
      const c = box(0.38, h, 0.38, statusColor(m), {edges: m.status === "Verified" ? MAP_COLORS.acid : 0x000000});
      c.position.set(x, base.y + h / 2, z); c.userData = {tid:t.id, h};
      root.add(c); MAPS.pick.push(c);
      if (m.reach){
        const ring = new THREE.Mesh(new THREE.RingGeometry(0.3, 0.38, 24), new THREE.MeshBasicMaterial({color: m.proven ? MAP_COLORS.crit : MAP_COLORS.acid, side:THREE.DoubleSide, transparent:true}));
        ring.rotation.x = -Math.PI / 2; ring.position.set(x, base.y + 0.02, z); root.add(ring); MAPS.pulses.push(ring);
      }
    });
  });
  // path replay
  MAPS.route = null;
  const ap = M.paths.find(x => x.id === MAPS.path && x.applies);
  if (ap){
    const pts = [(MAPS.pos[ap.from] || MAPS.pos.atk).clone()];
    const blockedAt = ap.stages.findIndex(s => s.blocked);
    ap.stages.forEach(s => { let a = s.anchor; if (!MAPS.pos[a]){ a = ANCHOR[s.app[0]]; if (!MAPS.pos[a]) a = "app"; } const v = MAPS.pos[a].clone(); if (pts.some(q => q.distanceTo(v) < 0.1)) v.x += 0.9; pts.push(v); });
    pts.forEach(v => v.y = 1.25);
    const g = new THREE.BufferGeometry().setFromPoints(pts);
    for (let i = 0; i < pts.length - 1; i++){
      const A = pts[i], B = pts[i + 1], len = A.distanceTo(B);
      const cyl = new THREE.Mesh(new THREE.CylinderGeometry(0.07, 0.07, len, 8), new THREE.MeshLambertMaterial({color: (ap.blocked && i >= blockedAt) ? MAP_COLORS.line : MAP_COLORS.crit}));
      cyl.position.copy(A).lerp(B, 0.5); cyl.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), B.clone().sub(A).normalize()); root.add(cyl);
    }
    pts.forEach((v, i) => { if (!i) return; const st = ap.stages[i - 1];
      const d = box(0.5, 0.06, 0.5, st.blocked ? MAP_COLORS.acid : MAP_COLORS.crit); d.position.copy(v); root.add(d);
      MAPS.labels.push({pos:v.clone().setY(1.6), html:`<span class="ml-stage ${st.blocked ? "b" : ""}">${i}. ${esc(st.name)}</span>`, cls:"mls"}); });
    let gate = null;
    if (blockedAt >= 0){
      const A = pts[blockedAt], B = pts[blockedAt + 1], G = A.clone().lerp(B, 0.72);
      gate = box(0.2, 2.6, 2.0, MAP_COLORS.acid, {edges:MAP_COLORS.ink}); gate.position.set(G.x, 1.3, G.z);
      gate.lookAt(new THREE.Vector3(B.x, 1.3, B.z)); gate.rotateY(Math.PI / 2); root.add(gate);
    }
    const token = box(0.42, 0.42, 0.42, MAP_COLORS.crit, {edges:0x000000}); root.add(token);
    const target = pts[pts.length - 1];
    const flash = new THREE.Mesh(new THREE.RingGeometry(0.5, 0.7, 32), new THREE.MeshBasicMaterial({color:MAP_COLORS.crit, side:THREE.DoubleSide, transparent:true, opacity:0}));
    flash.rotation.x = -Math.PI / 2; flash.position.copy(target).setY(0.7); root.add(flash);
    MAPS.route = {pts, blockedAt, token, flash, gate, ap, t0:performance.now()};
  }
  mapPanel(M);
  mapOutline(M, comps, stacks);
}

function mapPanel(M){
  const el = $("#map-panel"); if (!el) return;
  if (MAPS.sel){
    const t = THR[MAPS.sel], m = M.threats[MAPS.sel];
    el.innerHTML = `<div class="mp-h"><span class="mono">${t.id}</span> ${riskPill(m.risk)} ${statPill(m.status)}</div><p><b>${esc(t.t)}</b></p><p class="small">${esc(t.s)}</p>
      <p class="small muted">Still needed: ${missingText(m.missing, true) || "nothing"}</p>
      ${m.findings.length ? `<p class="small">${gradePill(m.findings[0].grade)} ${m.findings.length} finding${m.findings.length > 1 ? "s" : ""}</p>` : ""}
      <div class="imp-row"><button type="button" class="primary" data-act="gothreat" data-id="${t.id}">Open in Threats</button><button type="button" data-act="mapclose">Close</button></div>`;
    el.hidden = false; return;
  }
  const r = MAPS.route;
  if (r){
    const ap = r.ap;
    el.innerHTML = `<div class="mp-h"><span class="mono">${ap.id}</span> ${ap.blocked ? `<span class="pill s-mitigated">Broken</span>` : `<span class="pill s-open">Open</span>`}</div><p><b>${esc(ap.t)}</b></p>
      <ol class="mp-stages">${ap.stages.map((s, i) => `<li class="${s.blocked ? "b" : ""}"><span>${esc(s.name)}</span> <span class="small muted">${s.app.join(", ")}</span>${s.blocked ? ` <span class="pill s-mitigated">Gate</span>` : ""}</li>`).join("")}</ol>
      <p class="small">${ap.blocked ? `Stopped at stage ${r.blockedAt + 1}. Every applicable threat there is mitigated.` : `Nothing stops it. Fewest missing controls at stage ${ap.cheapest + 1}: ${missingText({req:ap.stages[ap.cheapest].missing, groups:ap.stages[ap.cheapest].missingGroups}, true)}.`}</p>
      <p class="small muted">Detection ${ap.detOn.length}/${ap.dets.length} deployed. Seeing it is not stopping it.</p>`;
    el.hidden = false; return;
  }
  el.innerHTML = `<p class="small"><b>${M.app.length} threats</b> on ${Object.keys(MAPS.pos).length} components. Click a column for detail, or replay an attack path from the menu above.</p>`;
  el.hidden = false;
}

function mapOutline(M, comps, stacks){
  const o = $("#map-outline"); if (!o) return;
  o.innerHTML = `<ul>${ZONES.map(([z, name]) => `<li><b>${esc(name)}</b><ul>${comps.filter(c => c[2] === z).map(c => `<li>${esc(c[1])}${(stacks[c[0]] || []).length ? ": " + stacks[c[0]].map(t => `<button type="button" class="link" data-act="gothreat" data-id="${t.id}">${t.id}</button> ${M.threats[t.id].risk}, ${M.threats[t.id].status}`).join("; ") : ": no threats placed"}</li>`).join("")}</ul></li>`).join("")}</ul>`;
}

function mapPick(e, click){
  const r = MAPS.renderer.domElement.getBoundingClientRect();
  MAPS.ptr.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
  MAPS.ray.setFromCamera(MAPS.ptr, MAPS.camera);
  const hit = MAPS.ray.intersectObjects(MAPS.pick, false)[0];
  const tip = $("#map-tip");
  if (hit){
    const id = hit.object.userData.tid, m = M.threats[id];
    MAPS.renderer.domElement.style.cursor = "pointer";
    tip.innerHTML = `<span class="mono">${id}</span> ${esc(THR[id].t)}<br><span class="small">${m.risk} · ${m.status}${m.reach ? " · evidence" : ""}</span>`;
    tip.style.left = (e.clientX - r.left + 14) + "px"; tip.style.top = (e.clientY - r.top + 14) + "px"; tip.hidden = false;
    if (click){ MAPS.sel = id; mapPanel(M); }
  } else {
    MAPS.renderer.domElement.style.cursor = "grab"; tip.hidden = true;
    if (click && MAPS.sel){ MAPS.sel = null; mapPanel(M); }
  }
}

function mapFrame(now){
  if (UI.tab !== "map" || !MAPS.built){ MAPS.raf = 0; return; }
  MAPS.raf = requestAnimationFrame(mapFrame);
  if (!MAPS.w) mapResize();
  const cam = MAPS.camera, w = MAPS.w || 800, h = MAPS.h || 500, asp = w / h, half = 14.5 / MAPS.zoom;
  const pnl = $("#map-panel"), side = (pnl && !pnl.hidden && w > 760) ? (pnl.offsetWidth + 28) : 0;
  const shift = side / w * half * asp * 0.75;
  cam.left = -half * asp + shift; cam.right = half * asp + shift; cam.top = half; cam.bottom = -half; cam.updateProjectionMatrix();
  const R = 60;
  cam.position.set(R * Math.cos(MAPS.el) * Math.sin(MAPS.az), R * Math.sin(MAPS.el), R * Math.cos(MAPS.el) * Math.cos(MAPS.az));
  cam.lookAt(0, 0, 0);
  const still = reduceMotion() || MAPS.paused;
  const t = still ? 0 : now / 1000;
  MAPS.packets.forEach(pk => { const f = still ? 0.5 : (t * 0.35 + pk.off) % 1; pk.m.position.lerpVectors(pk.A, pk.B, f); });
  MAPS.pulses.forEach(r => { const s = still ? 1 : 1 + 0.45 * ((t * 0.9) % 1); r.scale.set(s, s, s); r.material.opacity = still ? 0.9 : 1 - ((t * 0.9) % 1) * 0.8; });
  const rt = MAPS.route;
  if (rt){
    const segs = rt.pts.length - 1, SEG = 1.15, stopSeg = rt.blockedAt >= 0 ? rt.blockedAt : segs;
    const total = (stopSeg + (rt.blockedAt >= 0 ? 0.62 : 0)) * SEG + 1.4;
    const el = still ? total - 0.01 : (Math.max(0, now - rt.t0) / 1000) % total;
    let prog = Math.max(0, Math.min(el / SEG, stopSeg + (rt.blockedAt >= 0 ? 0.62 : 0)));
    const si = Math.min(Math.floor(prog), segs - 1), f = prog - si;
    rt.token.position.lerpVectors(rt.pts[si], rt.pts[si + 1], Math.min(f, 1));
    rt.token.rotation.y = t * 2;
    const arrived = rt.blockedAt < 0 && prog >= segs - 0.001;
    rt.flash.material.opacity = arrived ? 0.85 : 0; if (arrived){ const s = 1 + ((el - segs * SEG) % 0.7) * 1.4; rt.flash.scale.set(s, s, s); }
    if (rt.gate){ const hitGate = rt.blockedAt >= 0 && prog >= rt.blockedAt + 0.6; rt.gate.material.color.setHex(hitGate ? 0xe9ff8a : MAP_COLORS.acid); }
  }
  MAPS.renderer.render(MAPS.scene, cam);
  // labels
  const lab = $("#map-labels");
  if (lab.childElementCount !== MAPS.labels.length){ lab.innerHTML = MAPS.labels.map(l => `<div class="ml ${l.cls}">${l.html}</div>`).join(""); }
  const kids = lab.children, v = new THREE.Vector3();
  MAPS.labels.forEach((l, i) => { v.copy(l.pos).project(cam); const x = (v.x + 1) / 2 * w, y = (1 - v.y) / 2 * h; kids[i].style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`; });
}

function renderMap(M){
  if (!mapInit()) return;
  if (UI.mapPath){ MAPS.path = UI.mapPath; UI.mapPath = ""; }
  const sel = $("#map-path");
  const opts = M.paths.map(p => `<option value="${p.id}" ${p.applies ? "" : "disabled"} ${MAPS.path === p.id ? "selected" : ""}>${p.id} ${esc(p.t)}${p.applies ? (p.blocked ? " (broken)" : " (open)") : " (does not apply)"}</option>`).join("");
  sel.innerHTML = `<option value="">None</option>` + opts;
  if (MAPS.path && !M.paths.find(p => p.id === MAPS.path && p.applies)) MAPS.path = "";
  sel.value = MAPS.path;
  $("#map-play").textContent = MAPS.paused ? "Play" : "Pause";
  mapBuild(M);
  $("#map-labels").innerHTML = "";
  mapResize();
  if (!MAPS.raf) MAPS.raf = requestAnimationFrame(mapFrame);
}
document.addEventListener("change", e => { if (e.target.id === "map-path"){ MAPS.path = e.target.value; MAPS.sel = null; renderMap(M); } });
document.addEventListener("click", e => {
  const el = e.target.closest("[data-act]"); if (!el) return;
  const a = el.dataset.act;
  if (a === "mapplay"){ MAPS.paused = !MAPS.paused; el.textContent = MAPS.paused ? "Play" : "Pause"; }
  else if (a === "mapreset"){ MAPS.az = Math.PI * 0.25; MAPS.el = 0.62; MAPS.zoom = 1; }
  else if (a === "maptop"){ MAPS.az = 0; MAPS.el = 1.45; }
  else if (a === "mapclose"){ MAPS.sel = null; mapPanel(M); }
});
