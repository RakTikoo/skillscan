"""CLI entry point: python3 -m skillscan <folder-or-github-url>
                   [--format text|json|md|sarif] [--llm]

Two modes, clearly demarcated. OFFLINE (default): the deterministic
scanner only — no network, same folder always gets the same verdict.
LLM (--llm): additionally sends the skill's PROSE (never code) to a
language model for a second opinion on semantic steering. The LLM can
only ADD findings; the offline verdict and findings are never altered,
and the combined verdict is max(offline, llm), labelled with its
source. Exit codes: 0 = PASS, 1 = CAUTION, 2 = BLOCK (of the combined
verdict when --llm is on; of the offline verdict otherwise and
whenever the LLM review is unavailable), 3 = usage / IO error (the
scanner could not run at all — deliberately distinct from BLOCK).
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
from .scanner import VERDICT_EXIT_CODES, ScanResult, scan_folder


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


def _no_steering_line(review) -> str:
    """The no-findings line, worded so it never overclaims coverage:
    a partial review says so, and a review that fully reviewed no
    file does not claim a clean pass over prose it never judged."""
    if review.files_reviewed == 0:
        return ("No steering verdict: no prose file was fully "
                "reviewed (see above).")
    if review.status == "partial":
        return ("No steering found in the prose reviewed (partial "
                "coverage — see Not reviewed above).")
    return "No steering found in the prose reviewed."


def _llm_text_lines(review, combined: str, source: str,
                    offline: str) -> list[str]:
    """The LLM section of the text report. Clearly headed and separate:
    the offline verdict above it is never rewritten by this section."""
    lines = [
        "",
        f"LLM review (model: {review.model}, via {review.base_url})",
        "  NON-DETERMINISTIC: a language model's second opinion on the "
        "skill's prose.",
        "  It can only ADD findings — it can never clear or change the "
        "offline verdict or any finding above.",
    ]
    if review.status == "unavailable":
        lines.append(f"  Status: UNAVAILABLE — {review.error}")
        lines.append("  The offline verdict stands on its own.")
    else:
        lines.append(
            f"  Status: {review.status} — reviewed "
            f"{review.files_reviewed} of {review.files_total} prose "
            f"file(s), {review.chunks_reviewed} of "
            f"{review.chunks_total} chunk(s).")
        for note in review.notes:
            lines.append(f"  Note: {note}")
        for u in review.unreviewed:
            lines.append(
                f"  Not reviewed: {_clean(u['file'])} ({u['reason']})")
        if review.dropped:
            lines.append(
                f"  Dropped {review.dropped} steering claim(s) whose "
                f"evidence quote was not in the text sent.")
        if review.findings:
            lines.append(f"  LLM findings ({len(review.findings)}):")
            for f in review.findings:
                lines.append(
                    f"    [{f.severity.upper()}] {f.rule} — "
                    f"{_clean(f.file)}:{f.line}")
                lines.append(f"      {f.reason}")
                if f.evidence:
                    lines.append(f"      > {_clean(f.evidence)}")
        else:
            lines.append(f"  {_no_steering_line(review)}")
    lines.append("")
    lines.append(f"COMBINED VERDICT: {combined} (source: {source})")
    return lines


def render_text(result: ScanResult, review=None, combined: str | None = None,
                source: str = "offline") -> str:
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
    if review is None:
        lines.append(f"VERDICT: {result.verdict}")
    else:
        lines.append(f"VERDICT (offline): {result.verdict}")
        lines += _llm_text_lines(review, combined or result.verdict,
                                 source, result.verdict)
    return "\n".join(lines)


def render_md(result: ScanResult, review=None, combined: str | None = None,
              source: str = "offline") -> str:
    verdict_label = "VERDICT" if review is None else "VERDICT (offline)"
    lines = [
        "# SkillScan report",
        "",
        f"Target: `{_clean(result.target)}`",
        "",
        f"**{verdict_label}: {result.verdict}**",
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
    if review is not None:
        lines += [
            "## LLM review",
            "",
            f"Model: `{review.model}` via `{review.base_url}` — "
            "**non-deterministic** second opinion on the skill's prose. "
            "It can only add findings; it can never clear or change "
            "the offline verdict or any finding above.",
            "",
        ]
        if review.status == "unavailable":
            lines.append(f"Status: **UNAVAILABLE** — {review.error}")
            lines.append("")
            lines.append("The offline verdict stands on its own.")
        else:
            lines.append(
                f"Status: **{review.status}** — reviewed "
                f"{review.files_reviewed} of {review.files_total} "
                f"prose file(s), {review.chunks_reviewed} of "
                f"{review.chunks_total} chunk(s).")
            for note in review.notes:
                lines.append(f"- Note: {note}")
            for u in review.unreviewed:
                lines.append(
                    f"- Not reviewed: `{_clean(u['file'])}` "
                    f"({u['reason']})")
            if review.dropped:
                lines.append(
                    f"- Dropped {review.dropped} steering claim(s) "
                    f"whose evidence quote was not in the text sent.")
            lines.append("")
            if review.findings:
                lines += ["| Severity | Rule | Location | Reason | Evidence |",
                          "|---|---|---|---|---|"]
                for f in review.findings:
                    reason = f.reason.replace("|", "\\|")
                    evidence = _clean(f.evidence).replace("|", "\\|").replace("`", "'")
                    lines.append(
                        f"| {f.severity.upper()} | {f.rule} | "
                        f"{_clean(f.file)}:{f.line} | {reason} | "
                        f"`{evidence}` |")
            else:
                lines.append(_no_steering_line(review))
        lines.append("")
        lines.append(
            f"**COMBINED VERDICT: {combined or result.verdict}** "
            f"(source: {source})")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SARIF 2.1.0 output (for GitHub code scanning, IDEs, other toolchains)
# ---------------------------------------------------------------------------

_SARIF_LEVELS = {"block": "error", "caution": "warning"}


def render_sarif(result: ScanResult, review=None,
                 combined: str | None = None,
                 source: str = "offline") -> str:
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
                "owasp": rule.owasp,
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
    properties = {
        "verdict": result.verdict,
        "scannedFiles": result.scanned_files,
        "skippedFiles": len(result.skipped),
    }
    if review is not None:
        # The LLM lane is demarcated in SARIF too: its findings carry
        # their own rule id (declared here, only in --llm runs), and
        # the combined verdict lives in properties next to — never
        # instead of — the offline "verdict" property.
        if review.findings:
            rules.append({
                "id": "LLM_STEERING",
                "name": "LLM_STEERING",
                "shortDescription": {
                    "text": "Semantic prose steering (LLM review)"},
                "fullDescription": {
                    "text": "Prose that steers the agent into "
                            "misleading the user, flagged by the "
                            "optional LLM review. Non-deterministic."},
                "help": {
                    "text": "Prose that steers the agent into "
                            "misleading the user, flagged by the "
                            "optional LLM review. Non-deterministic."},
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "security-severity": "5.0",
                    "tags": ["security", "llm-review"],
                    "owasp": [],
                },
            })
            for f in review.findings:
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
                        "skillscan/llm-v1":
                            f"{f.rule}:{_clean(f.file)}:{f.line}",
                    },
                }
                if f.evidence:
                    entry["message"]["text"] = \
                        f"{f.reason} Evidence: {_clean(f.evidence)}"
                results.append(entry)
        properties["llmReview"] = review.to_dict()
        properties["combinedVerdict"] = combined or result.verdict
        properties["verdictSource"] = source
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
            "properties": properties,
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


def _emit(result: ScanResult, fmt: str, review=None,
          combined: str | None = None, source: str = "offline") -> None:
    if fmt == "json":
        data = result.to_dict()
        if review is not None:
            # Offline fields stay exactly as they are; the LLM lane is
            # one added object, carrying the combined verdict inside it.
            llm = review.to_dict()
            llm["combined_verdict"] = combined or result.verdict
            llm["verdict_source"] = source
            llm["combined_exit_code"] = \
                VERDICT_EXIT_CODES[combined or result.verdict]
            data["llm"] = llm
        print(json.dumps(data, indent=2))
    elif fmt == "md":
        print(render_md(result, review, combined, source))
    elif fmt == "sarif":
        print(render_sarif(result, review, combined, source))
    else:
        print(render_text(result, review, combined, source))


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
    parser.add_argument(
        "--llm", action="store_true",
        help="Also run the optional LLM review: the skill's prose "
             "(never code) is sent to a language model for a second "
             "opinion on semantic steering. Non-deterministic. The "
             "LLM can only ADD findings — the offline verdict and "
             "findings are never changed, and the exit code follows "
             "the combined verdict. Needs an API key in "
             "SKILLSCAN_LLM_API_KEY (GROQ_API_KEY is accepted only "
             "for the Groq preset endpoint). Without --llm "
             "the scan is fully offline and deterministic, exactly "
             "as before.",
    )
    parser.add_argument(
        "--llm-model", default=None,
        help="Model for --llm (default: qwen/qwen3.8-27b, the "
             "Groq reference preset's measured free-tier model; any "
             "model on any OpenAI-compatible endpoint works)",
    )
    parser.add_argument(
        "--llm-base-url", default=None,
        help="OpenAI-compatible chat-completions base URL for --llm "
             "(default: the Groq preset, "
             "https://api.groq.com/openai/v1)",
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
        if not args.llm:
            _emit(result, args.format)
            return result.exit_code
        # LLM mode: the offline result above is final and untouched.
        # The review is a separate, additive pass whose failures
        # degrade to UNAVAILABLE inside the report — never to a crash
        # and never to a changed offline verdict. The llm module (and
        # with it urllib) is imported only on this path: an offline
        # run never touches the network stack.
        from . import llm as _llm

        cfg = _llm.config_from_env(model=args.llm_model,
                                   base_url=args.llm_base_url)
        try:
            review = _llm.review_folder(target, result.findings, cfg)
        except Exception as exc:  # belt and braces: review must not crash
            review = _llm.LlmReview(
                status="unavailable", model=cfg.model,
                base_url=cfg.base_url,
                error=f"review failed ({type(exc).__name__})")
        combined, source = _llm.combined_verdict(result.verdict, review)
        _emit(result, args.format, review, combined, source)
        return VERDICT_EXIT_CODES[combined]
    finally:
        if clone_root is not None:
            shutil.rmtree(clone_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
