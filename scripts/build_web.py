"""Build docs/index.html (GitHub Pages) by inlining web/engine.js into the page template.

  python scripts/build_web.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
tpl = (ROOT / "web/index.template.html").read_text()
engine = (ROOT / "web/engine.js").read_text()
assert "/*ENGINE*/" in tpl
out = ROOT / "docs/index.html"
out.parent.mkdir(exist_ok=True)
out.write_text(tpl.replace("/*ENGINE*/", engine))
(ROOT / "docs/.nojekyll").write_text("")
print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
