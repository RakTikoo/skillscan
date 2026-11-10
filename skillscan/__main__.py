"""CLI entry point: python3 -m skillscan <folder-or-github-url>
                   [--format text|json|md|sarif]

Exit codes: 0 = PASS, 1 = CAUTION, 2 = BLOCK, 3 = usage / IO error
(the scanner could not run at all — deliberately distinct from BLOCK).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .rules import RULES
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


# ---------------------------------------------------------------------------
# SARIF 2.1.0 output (for GitHub code scanning, IDEs, other toolchains)
# ---------------------------------------------------------------------------

_SARIF_LEVELS = {"block": "error", "caution": "warning"}


def render_sarif(result: ScanResult) -> str:
    rules = []
    for rule in RULES:
        rules.append({
            "id": rule.id,
            "name": rule.id,
            "shortDescription": {"text": rule.id.replace("_", " ").title()},
            "fullDescription": {"text": rule.reason},
            "help": {"text": rule.reason},
            "defaultConfiguration": {"level": _SARIF_LEVELS[rule.severity]},
            "properties": {
                "security-severity": "8.0" if rule.severity == "block" else "5.0",
                "tags": ["security"],
            },
        })
    results = []
    for f in result.findings:
        entry = {
            "ruleId": f.rule,
            "level": _SARIF_LEVELS.get(f.severity, "warning"),
            "message": {"text": f.reason},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _clean(f.file)},
                    "region": {"startLine": max(f.line, 1)},
                },
            }],
            "partialFingerprints": {
                "skillscan/v1": f"{f.rule}:{_clean(f.file)}:{f.line}:{f.count}",
            },
        }
        if f.evidence:
            entry["message"]["text"] = f"{f.reason} Evidence: {_clean(f.evidence)}"
        results.append(entry)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SkillScan",
                    "version": __version__,
                    "informationUri": "https://github.com/RakTikoo/skillscan",
                    "rules": rules,
                },
            },
            "results": results,
            "properties": {
                "verdict": result.verdict,
                "scannedFiles": result.scanned_files,
                "skippedFiles": len(result.skipped),
            },
        }],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# Scanning a GitHub repo URL: shallow clone into a temp dir, scan, clean up
# ---------------------------------------------------------------------------

_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?$")
_MAX_CLONE_BYTES = 1_000_000_000


def _is_url(text: str) -> bool:
    return text.startswith(("http://", "https://"))


def _clone_github_repo(url: str) -> Path | None:
    """Validate and shallow-clone a github.com repo URL into a fresh temp
    dir (returned; caller owns cleanup). None = usage/IO error (exit 3).

    Only https://github.com/<owner>/<repo> is accepted — no other host,
    no credentials in the URL, no query/fragment. Redirect following is
    disabled so a clone can never be silently redirected off github.com.
    """
    parsed = urlparse(url)
    clean = url.rstrip("/")
    if clean.endswith(".git"):
        clean = clean[: -len(".git")]
    segments = clean[len("https://github.com/"):].split("/") \
        if clean.startswith("https://github.com/") else []
    if parsed.scheme != "https" or parsed.hostname != "github.com" \
            or parsed.username or parsed.password or parsed.query \
            or parsed.fragment or not _GITHUB_URL_RE.fullmatch(clean) \
            or len(segments) != 2 or any(s in (".", "..") for s in segments):
        print(f"error: only https://github.com/<owner>/<repo> URLs can be "
              f"scanned: {url}", file=sys.stderr)
        return None
    if shutil.which("git") is None:
        print("error: scanning a repo URL needs git on PATH, and git was "
              "not found", file=sys.stderr)
        return None
    tmp = Path(tempfile.mkdtemp(prefix="skillscan-clone-"))
    dest = tmp / "repo"
    try:
        proc = subprocess.run(
            ["git", "-c", "http.followRedirects=false",
             "clone", "--depth", "1",
             # Partial clone: blobs over the per-file scan cap (2 MB) are
             # not downloaded up front — the scanner cannot use them
             # anyway, and its coverage machinery reports oversize files
             # as skipped rather than pretending they were scanned.
             "--filter=blob:limit=2097152", "--", clean, str(dest)],
            capture_output=True, text=True, timeout=120,
            # Inherit the caller's environment (proxy settings etc. are
            # needed for git to reach github.com at all); just make sure
            # git can never block on an interactive credential prompt.
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"error: git clone failed: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    if proc.returncode != 0 or not dest.is_dir():
        print("error: git clone failed for "
              f"{clean}: {proc.stderr.strip()[:300]}", file=sys.stderr)
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    # Post-clone size check: the blob filter limits the initial pack,
    # but checkout can still backfill large blobs. A skill repo has no
    # business being enormous — refuse (exit 3) rather than scan a
    # multi-GB tree. The scanner's own budgets (2 MB/file, 32 MB/scan)
    # apply below this cap and report partial coverage honestly.
    total = 0
    for dirpath, _dirnames, filenames in os.walk(dest):
        if ".git" in Path(dirpath).parts:
            continue
        for name in filenames:
            try:
                total += (Path(dirpath) / name).stat().st_size
            except OSError:
                pass
    if total > _MAX_CLONE_BYTES:
        print(f"error: cloned repo is {total} bytes, over the "
              f"{_MAX_CLONE_BYTES}-byte limit for URL scans", file=sys.stderr)
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    return dest


def _emit(result: ScanResult, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result.to_dict(), indent=2))
    elif fmt == "md":
        print(render_md(result))
    elif fmt == "sarif":
        print(render_sarif(result))
    else:
        print(render_text(result))


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        prog="skillscan",
        description="Scan an AI-agent skill or MCP server folder before you install it.",
    )
    parser.add_argument(
        "folder",
        help="Path to the skill / MCP server folder to scan, or an "
             "https://github.com/<owner>/<repo> URL to clone and scan")
    parser.add_argument(
        "--format", choices=["text", "json", "md", "sarif"], default="text",
        help="Report format (default: text)",
    )
    args = parser.parse_args(argv)

    clone_root: Path | None = None
    if _is_url(args.folder):
        dest = _clone_github_repo(args.folder)
        if dest is None:
            return 3
        clone_root = dest.parent
        target = dest
    else:
        target = Path(args.folder)
        if not target.is_dir():
            print(f"error: not a folder: {args.folder}", file=sys.stderr)
            return 3

    try:
        try:
            result = scan_folder(target)
        except Exception as exc:  # never answer a folder with a traceback
            print(f"error: scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 3
        _emit(result, args.format)
        return result.exit_code
    finally:
        if clone_root is not None:
            shutil.rmtree(clone_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
