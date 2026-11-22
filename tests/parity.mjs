// Usage: node tests/parity.mjs <dir> [<dir>...]  -> JSON {dir: findings[]} on stdout
// tests/test_parity.py compares this with the Python scanner.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const pf = require("../web/engine.js");

function walk(root) {
  const out = [];
  (function rec(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) rec(p);
      else if (e.isFile()) {
        const rel = path.relative(root, p).split(path.sep).join("/");
        if (!pf.shouldScan(rel)) continue;
        if (fs.statSync(p).size > 2_000_000) continue;
        out.push({ path: rel, text: fs.readFileSync(p).toString("utf8") });
      }
    }
  })(root);
  return out;
}
const res = {};
for (const d of process.argv.slice(2)) res[d] = pf.scan(walk(d)).findings;
process.stdout.write(JSON.stringify(res));
