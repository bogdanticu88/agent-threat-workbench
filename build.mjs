// Builds index.html from src/. No dependencies: node build.mjs
import {readFileSync, writeFileSync} from "node:fs";
const r = f => readFileSync(new URL(f, import.meta.url), "utf8");
const sample = JSON.stringify(JSON.parse(r("./examples/overreach-sample.json")));
let html = r("./src/shell.html");
const parts = {
  "/*SAMPLE*/": `const SAMPLE_OVERREACH = ${sample};`,
  "/*CATALOG*/": r("./src/catalog.js"),
  "/*MODEL*/": r("./src/model.js").replace(/^if \(typeof module[^\n]*\n?/m, ""),
  "/*APP*/": r("./src/app.js"),
  "/*MAP*/": r("./src/map3d.js")
};
for (const [k, v] of Object.entries(parts)){
  if (!html.includes(k)) throw new Error("Missing placeholder " + k);
  html = html.replace(k, () => v);
}
writeFileSync(new URL("./index.html", import.meta.url), html);
console.log(`index.html written, ${(html.length / 1024).toFixed(0)} KB`);
