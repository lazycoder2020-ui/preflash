"""Run with:  python -m pytest  (or just: python tests/test_rules.py)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preflash.project import load            # noqa: E402
from preflash.rules import run_all, is_placeholder   # noqa: E402

FIX = Path(__file__).parent / "fixtures"


def rules_hit(path):
    _, files = load(path)
    return {f.rule for f in run_all(files)}


def test_vulnerable_sketch_catches_everything():
    hit = rules_hit(FIX / "vulnerable")
    expected = {"PF001", "PF002", "PF003", "PF005", "PF006", "PF007", "PF008",
                "PF009", "PF010", "PF011", "PF012", "PF013", "PF014"}
    assert expected <= hit, f"missing: {expected - hit}"


def test_clean_sketch_has_no_findings():
    assert rules_hit(FIX / "clean") == set()


def test_placeholders():
    for v in ["YOUR_PASSWORD", "", "********", "wifiPass", "WIFI PASS",
              "my password", "password", "<password>", "xxxx"]:
        assert is_placeholder(v), v
    for v in ["greenhouse2024!", "Nitesh@7349478091", "86669443", "school100"]:
        assert not is_placeholder(v), v


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
