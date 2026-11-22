"""Check the browser engine (web/engine.js) gives identical results to the Python scanner.

  python tests/test_parity.py [dirs...]      (defaults to tests/fixtures/*)
Needs Node 18+.
"""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from preflash.project import load      # noqa: E402
from preflash.rules import run_all     # noqa: E402

KEYS = ("rule", "severity", "file", "line", "message", "snippet")


def py(d):
    _, files = load(Path(d))
    return [{k: (str(v).replace("\\", "/") if k == "file" else v)
             for k, v in x.to_dict().items() if k in KEYS} for x in run_all(files)]


def main(dirs):
    js = json.loads(subprocess.run(["node", str(ROOT / "tests/parity.mjs"), *dirs],
                                   capture_output=True, text=True, check=True).stdout)
    bad = 0
    for d in dirs:
        a = py(d)
        b = [{k: x[k] for k in KEYS} for x in js[d]]
        if a != b:
            bad += 1
            sa = {json.dumps(x, sort_keys=True) for x in a}
            sb = {json.dumps(x, sort_keys=True) for x in b}
            print(f"MISMATCH {d}: python-only={len(sa - sb)} js-only={len(sb - sa)}")
            for x in list(sa - sb)[:3]: print("  py:", x)
            for x in list(sb - sa)[:3]: print("  js:", x)
    print(f"{len(dirs) - bad}/{len(dirs)} identical")
    return bad


def test_parity_fixtures():
    assert main([str(p) for p in sorted((ROOT / "tests/fixtures").iterdir())]) == 0


if __name__ == "__main__":
    dirs = sys.argv[1:] or [str(p) for p in sorted((ROOT / "tests/fixtures").iterdir())]
    sys.exit(1 if main(dirs) else 0)
