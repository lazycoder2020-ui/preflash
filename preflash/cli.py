"""preflash - security scanner for Arduino / ESP32 / ESP8266 code. Scan before you flash.

  preflash .                      scan the current project
  preflash src/ --format sarif    output for GitHub code scanning
  preflash . --fail-on medium     non-zero exit if anything medium or worse
"""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .project import load
from .rules import RULES, SEV_ORDER, run_all

COLOURS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
           "low": "\033[36m", "dim": "\033[2m", "bold": "\033[1m", "end": "\033[0m"}


def text_report(findings, nfiles, colour):
    c = (lambda k: COLOURS[k]) if colour else (lambda k: "")
    lines = []
    if not findings:
        lines.append(f"{c('bold')}No issues found{c('end')} in {nfiles} file(s).")
        return "\n".join(lines)
    for x in findings:
        sev = x.severity.upper()
        lines.append(f"{c(x.severity)}{sev:<8}{c('end')} {c('bold')}{x.rule} {x.title}{c('end')}")
        lines.append(f"         {x.file}:{x.line}")
        if x.snippet:
            lines.append(f"         {c('dim')}{x.snippet}{c('end')}")
        lines.append(f"         {x.message}")
        lines.append(f"         Fix: {x.fix}")
        lines.append("")
    counts = {s: sum(1 for x in findings if x.severity == s) for s in SEV_ORDER}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    lines.append(f"{c('bold')}{len(findings)} issue(s){c('end')} in {nfiles} file(s): {summary}")
    return "\n".join(lines)


def sarif_report(findings):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    used = sorted({x.rule for x in findings})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "preflash", "version": __version__,
                "informationUri": "https://github.com/lazycoder2020-ui/preflash",
                "rules": [{
                    "id": rid, "name": RULES[rid]["title"],
                    "shortDescription": {"text": RULES[rid]["title"]},
                    "help": {"text": RULES[rid]["fix"]},
                    "properties": {"security-severity":
                                   {"critical": "9.5", "high": "8.0",
                                    "medium": "5.5", "low": "3.0"}[RULES[rid]["severity"]],
                                   "tags": ["security", "iot"]},
                } for rid in used],
            }},
            "results": [{
                "ruleId": x.rule, "level": level[x.severity],
                "message": {"text": f"{x.message} Fix: {x.fix}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": x.file.replace("\\", "/")},
                    "region": {"startLine": x.line}}}],
            } for x in findings],
        }],
    }


def main(argv=None):
    p = argparse.ArgumentParser(prog="preflash", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", nargs="?", default=".", type=Path)
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", type=Path, help="write report to a file")
    p.add_argument("--fail-on", choices=list(SEV_ORDER) + ["never"], default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--include-libs", action="store_true",
                   help="also scan lib/ and libraries/ folders")
    p.add_argument("--rules", help="comma-separated rule ids to run, e.g. PF001,PF005")
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"preflash {__version__}")
    a = p.parse_args(argv)

    if a.list_rules:
        for rid, r in RULES.items():
            print(f"{rid}  {r['severity']:<8}  {r['title']}")
        return 0

    if not a.path.exists():
        print(f"preflash: {a.path} not found", file=sys.stderr)
        return 2
    _, files = load(a.path, include_libs=a.include_libs)
    only = set(a.rules.upper().split(",")) if a.rules else None
    findings = run_all(files, only)

    if a.format == "json":
        out = json.dumps({"files_scanned": len(files),
                          "findings": [x.to_dict() for x in findings]}, indent=2)
    elif a.format == "sarif":
        out = json.dumps(sarif_report(findings), indent=2)
    else:
        colour = not a.no_color and sys.stdout.isatty() and not a.output
        out = text_report(findings, len(files), colour)

    if a.output:
        a.output.write_text(out)
    else:
        print(out)

    if a.fail_on != "never" and any(SEV_ORDER[x.severity] >= SEV_ORDER[a.fail_on]
                                    for x in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
