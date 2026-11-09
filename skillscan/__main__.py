"""CLI entry point: python3 -m skillscan <folder> [--format text|json|md]

Exit codes: 0 = PASS, 1 = CAUTION, 2 = BLOCK, 3 = usage / IO error
(the scanner could not run at all — deliberately distinct from BLOCK).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanResult, scan_folder


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # usage errors exit 3, not 2
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def _clean(text: str) -> str:
    """Make untrusted text safe to print to a terminal or paste into a
    document. File names and evidence lines come from the scanned folder —
    an attacker's folder — so control characters (ANSI escapes, carriage
    returns, NULs, …) are replaced with visible \\xNN escapes instead of
    being allowed to manipulate the reader's terminal or forge report
    lines. (JSON output does not need this: json.dumps already escapes
    control characters in its encoding.)"""
    out = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _coverage_lines(result: ScanResult) -> list[str]:
    lines = [f"Scanned {result.scanned_files} file(s); skipped {len(result.skipped)}."]
    for s in result.skipped:
        flag = " — NOT covered by this verdict" if s.suspicious else ""
        lines.append(f"  skipped: {_clean(s.file)} ({_clean(s.reason)}){flag}")
    return lines


def render_text(result: ScanResult) -> str:
    lines = [f"SkillScan report for: {_clean(result.target)}", ""]
    lines += _coverage_lines(result)
    lines.append("")
    if not result.findings:
        lines.append("No known-bad patterns found.")
    else:
        lines.append(f"Findings ({len(result.findings)}):")
        for f in result.findings:
            count = f" (x{f.count})" if f.count > 1 else ""
            lines.append(
                f"  [{f.severity.upper()}] {f.rule} — {_clean(f.file)}:{f.line}{count}"
            )
            lines.append(f"      {f.reason}")
            if f.evidence:
                lines.append(f"      > {_clean(f.evidence)}")
    lines.append("")
    lines.append(f"VERDICT: {result.verdict}")
    return "\n".join(lines)


def render_md(result: ScanResult) -> str:
    lines = [
        "# SkillScan report",
        "",
        f"Target: `{_clean(result.target)}`",
        "",
        f"**VERDICT: {result.verdict}**",
        "",
    ]
    lines += _coverage_lines(result)
    lines.append("")
    if result.findings:
        lines += ["| Severity | Rule | Location | Count | Reason | Evidence |",
                  "|---|---|---|---|---|---|"]
        for f in result.findings:
            reason = f.reason.replace("|", "\\|")
            evidence = _clean(f.evidence).replace("|", "\\|").replace("`", "'")
            lines.append(
                f"| {f.severity.upper()} | {f.rule} | {_clean(f.file)}:{f.line} | "
                f"{f.count} | {reason} | `{evidence}` |"
            )
    else:
        lines.append("No known-bad patterns found.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        prog="skillscan",
        description="Scan an AI-agent skill or MCP server folder before you install it.",
    )
    parser.add_argument("folder", help="Path to the skill / MCP server folder to scan")
    parser.add_argument(
        "--format", choices=["text", "json", "md"], default="text",
        help="Report format (default: text)",
    )
    args = parser.parse_args(argv)

    target = Path(args.folder)
    if not target.is_dir():
        print(f"error: not a folder: {args.folder}", file=sys.stderr)
        return 3

    try:
        result = scan_folder(target)
    except Exception as exc:  # never answer a folder with a traceback
        print(f"error: scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    elif args.format == "md":
        print(render_md(result))
    else:
        print(render_text(result))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
