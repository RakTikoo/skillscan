"""SkillScan scanner: walks a skill folder, applies deterministic rules,
and produces a BLOCK / CAUTION / PASS verdict.

Deterministic only: regex line rules (rules.py), Python `ast` checks with
constant folding and import-alias resolution, shell variable expansion,
and structural checks of JSON / MCP manifests. No LLM, no network, no
execution of scanned code — files are only ever read as text / parsed as
syntax trees.

Coverage honesty: every file that cannot be scanned (unreadable, oversized,
special file such as a FIFO, symlink, binary-looking content in a text-like
file) is recorded in the result, and suspicious skips stop the verdict from
being a clean PASS.
"""

from __future__ import annotations

import ast
import io
import json
import math
import os
import re
import stat
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

from .rules import LINE_RULES, RULES_BY_ID

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}
MAX_FILE_BYTES = 2_000_000
# Whole-scan budgets: the scanner reads UNTRUSTED folders, so a hostile or
# pathological folder must not be able to make it run forever or exhaust
# memory. Exceeding a budget stops the scan and is reported as a suspicious
# skip, which forces SCAN_INCOMPLETE (verdict can no longer be a clean PASS).
MAX_TOTAL_FILES = 2000
MAX_TOTAL_BYTES = 32_000_000
# Lines longer than this are truncated before rule matching, so a single
# enormous line cannot make regex matching (or reviewers) work unboundedly.
# Evidence snippets were already capped at 160 chars.
MAX_LINE_CHARS = 100_000

DOC_EXTENSIONS = {".md", ".txt", ".rst", ".adoc", ".yaml", ".yml", ".mdc"}
DOC_NAMES = {"LICENSE", "LICENCE", "CHANGELOG", "NOTICE", ".CURSORRULES"}
# Extensions where binary content is ordinary (images, archives, compiled
# artefacts). Skipping them is reported but does not taint the verdict.
KNOWN_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    ".pdf", ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class",
    ".pyc", ".mp3", ".mp4", ".wav", ".mov", ".avi", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".sqlite", ".db",
}
# Extensions treated as text-like: binary-looking content here is suspicious.
TEXTLIKE_EXTENSIONS = {
    ".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".sh", ".bash",
    ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl", ".php",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".md", ".txt",
    ".env", ".pyw", "",
}

VERDICT_EXIT_CODES = {"PASS": 0, "CAUTION": 1, "BLOCK": 2}

CREDENTIAL_RULES = {
    "SSH_CREDENTIAL_READ", "CLOUD_CREDENTIAL_READ", "ENV_FILE_READ",
    # A browser/wallet credential store counts as credential material for
    # the EXFIL_COMBINATION rule: store access + a send channel is the
    # stealer shape.
    "BROWSER_CREDENTIAL_STORE",
}
SEND_RULES = {"NETWORK_SEND_DATA"}
SECRET_NAME_RE = re.compile(r"(key|token|secret|password|passwd|credential|auth)", re.IGNORECASE)
NEGATION_RE = re.compile(
    r"\b(never|not|no|don'?t|do not|does not|refuse[sd]?|avoid|warning|forbidden|prohibited)\b",
    re.IGNORECASE,
)


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    reason: str
    evidence: str = ""
    count: int = 1


@dataclass
class Skipped:
    file: str
    reason: str
    suspicious: bool = False


@dataclass
class ScanResult:
    target: str
    verdict: str = "PASS"
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    skipped: list[Skipped] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return VERDICT_EXIT_CODES[self.verdict]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "scanned_files": self.scanned_files,
            "skipped_files": [
                {"file": s.file, "reason": s.reason, "suspicious": s.suspicious}
                for s in self.skipped
            ],
            "findings": [
                {
                    "rule": f.rule,
                    "severity": f.severity,
                    "file": f.file,
                    "line": f.line,
                    "reason": f.reason,
                    "evidence": f.evidence,
                    "count": f.count,
                }
                for f in self.findings
            ],
        }


# --------------------------------------------------------------------------
# File walking / decoding
# --------------------------------------------------------------------------

def _decode(raw: bytes) -> str | None:
    """Decode bytes to text, honouring BOMs. None = looks binary."""
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return raw.decode("utf-32", errors="replace").lstrip("\ufeff")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace").lstrip("\ufeff")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8", errors="replace").lstrip("\ufeff")
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _iter_files(root: Path, skipped: list[Skipped]):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            p = Path(dirpath) / d
            if d in SKIP_DIRS:
                continue
            if p.is_symlink():
                skipped.append(Skipped(str(p.relative_to(root)),
                                       "symlinked directory, not followed", True))
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            if path.is_symlink():
                skipped.append(Skipped(rel, "symlink, not followed", True))
                continue
            try:
                mode = path.stat().st_mode
            except OSError:
                skipped.append(Skipped(rel, "cannot stat file", True))
                continue
            if not stat.S_ISREG(mode):
                skipped.append(Skipped(rel, "special file (not a regular file)", True))
                continue
            yield path


def _is_doc(path: Path) -> bool:
    return path.suffix.lower() in DOC_EXTENSIONS or path.name.upper() in DOC_NAMES


# --------------------------------------------------------------------------
# Python AST: symbol tables, constant folding, call analysis
# --------------------------------------------------------------------------

def _raw_dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


class _Symbols:
    def __init__(self) -> None:
        self.alias: dict[str, str] = {}        # local name -> canonical module/dotted
        self.var_module: dict[str, str] = {}   # var -> module from import_module()
        self.var_callable: dict[str, str] = {}  # var -> dotted from getattr()
        self.var_obj: dict[str, str] = {}      # var -> module of object it was built from
        self.env_str: dict[str, str] = {}      # var -> folded string value
        self.env_list: dict[str, list] = {}    # var -> folded list value


def _fold_str(node: ast.AST, sym: _Symbols) -> str | None:
    """Best-effort constant folding of a string expression."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return sym.env_str.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold_str(node.left, sym), _fold_str(node.right, sym)
        if left is not None and right is not None:
            return left + right
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        # Path division: Path.home() / ".s"+"sh" / "id_"+"rsa" -> "~/.../..."
        left, right = _fold_str(node.left, sym), _fold_str(node.right, sym)
        if left is not None and right is not None:
            return left.rstrip("/") + "/" + right
        return None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                folded = _fold_str(value.value, sym)
                if folded is None:
                    return None
                parts.append(folded)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.Call):
        raw = _raw_dotted(node.func)
        if raw in ("Path.home", "os.path.expanduser") or raw.endswith(".home"):
            if raw.endswith("expanduser") and node.args:
                return _fold_str(node.args[0], sym)
            return "~"
        if raw in ("Path", "pathlib.Path"):
            parts = [_fold_str(a, sym) for a in node.args]
            if parts and all(p is not None for p in parts):
                return "/".join(parts)
            return None
        if raw == "chr" and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                try:
                    return chr(arg.value)
                except (ValueError, OverflowError):
                    return None
            return None
        if raw == "str" and len(node.args) == 1:
            return _fold_str(node.args[0], sym)
        # "sep".join([...]) / "".join(map(chr, [...]))
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and len(node.args) == 1:
            sep = _fold_str(node.func.value, sym)
            items = _fold_list(node.args[0], sym)
            if sep is not None and items is not None and all(isinstance(i, str) for i in items):
                return sep.join(items)
            arg = node.args[0]
            if (isinstance(arg, ast.Call) and _raw_dotted(arg.func) == "map"
                    and len(arg.args) == 2 and _raw_dotted(arg.args[0]) == "chr"):
                ints = _fold_list(arg.args[1], sym)
                if ints and all(isinstance(i, int) for i in ints):
                    try:
                        return "".join(chr(i) for i in ints)
                    except (ValueError, OverflowError):
                        return None
        return None
    if isinstance(node, ast.Subscript):
        # os.environ["HOME"]-shaped reads keep no string value we need.
        return None
    return None


def _fold_list(node: ast.AST, sym: _Symbols) -> list | None:
    if isinstance(node, (ast.List, ast.Tuple)):
        out = []
        for el in node.elts:
            if isinstance(el, ast.Constant) and isinstance(el.value, (str, int)):
                out.append(el.value)
            else:
                folded = _fold_str(el, sym)
                if folded is None:
                    return None
                out.append(folded)
        return out
    if isinstance(node, ast.Name):
        return sym.env_list.get(node.id)
    return None


def _resolve(node: ast.AST, sym: _Symbols) -> str:
    """Resolve a call's function expression to a canonical dotted name,
    honouring import aliases, importlib assignments and getattr()."""
    if isinstance(node, ast.Call):
        raw = _raw_dotted(node.func)
        if raw == "getattr" and len(node.args) >= 2:
            base = _resolve(node.args[0], sym) or _raw_dotted(node.args[0])
            attr = _fold_str(node.args[1], sym)
            if base and attr:
                return f"{base}.{attr}"
            return ""
        if raw in ("importlib.import_module", "import_module"):
            folded = _fold_str(node.args[0], sym) if node.args else None
            return folded or ""
        return ""
    raw = _raw_dotted(node)
    if not raw:
        return ""
    first, _, rest = raw.partition(".")
    if first in sym.var_callable and not rest:
        return sym.var_callable[first]
    if first in sym.var_obj:
        return sym.var_obj[first] + (f".{rest}" if rest else "")
    if first in sym.var_module:
        return sym.var_module[first] + (f".{rest}" if rest else "")
    if first in sym.alias:
        return sym.alias[first] + (f".{rest}" if rest else "")
    return raw


def _collect_symbols(tree: ast.AST, sym: _Symbols) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    sym.alias[a.asname] = a.name
                else:
                    sym.alias[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for a in node.names:
                    sym.alias[a.asname or a.name] = f"{node.module}.{a.name}"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                continue
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id
                if isinstance(value, ast.Call):
                    raw = _raw_dotted(value.func)
                    resolved_ctor = _resolve(value.func, sym)
                    if resolved_ctor and "." in resolved_ctor:
                        sym.var_obj[name] = resolved_ctor.rsplit(".", 1)[0]
                    if raw in ("importlib.import_module", "import_module") and value.args:
                        folded = _fold_str(value.args[0], sym)
                        if folded:
                            sym.var_module[name] = folded
                        continue
                    if raw == "getattr" and len(value.args) >= 2:
                        resolved = _resolve(value, sym)
                        if resolved:
                            sym.var_callable[name] = resolved
                        continue
                folded = _fold_str(value, sym)
                if folded is not None:
                    sym.env_str[name] = folded
                    continue
                lst = _fold_list(value, sym)
                if lst is not None:
                    sym.env_list[name] = lst


_AST_CALL_RULES = {
    "os.system": "SHELL_OS_SYSTEM",
    "os.popen": "SHELL_OS_SYSTEM",
    "eval": "EVAL_EXEC",
    "exec": "EVAL_EXEC",
    "__import__": "EVAL_EXEC",
    "os.remove": "FILE_DELETE",
    "os.unlink": "FILE_DELETE",
    "shutil.rmtree": "FILE_DELETE",
    "os.chmod": "CHMOD_CHOWN",
    "os.chown": "CHMOD_CHOWN",
}

_SEND_METHODS = {"post", "put", "patch"}
_HTTP_MODULES = {"requests", "httpx", "urllib"}


_PLACEHOLDER_ENV_RE = re.compile(
    r"\.env\.(example|sample|template|dist|defaults)\b", re.IGNORECASE)

# Browser / wallet credential-store fragments, matched against AST-folded
# string values so concatenated paths ("goo" + "gle-chr" + "ome") are
# caught the same way folded .ssh / .aws paths are.
_BROWSER_STORE_FRAGMENTS = (
    "Login Data", "logins.json", "key4.db", "cookies.sqlite",
    "Local State", "Local Extension Settings",
    "nkbihfbeogaeaoehlefnkodbefgpgknn", "wallet.dat", ".electrum",
    "google-chrome", "BraveSoftware", "Chrome/User Data",
    "Edge/User Data", "mozilla/firefox", "User Data/Default",
    "User Data/Profile",
)


def _check_credential_value(value: str, rel: str, line: int, add) -> None:
    if ".ssh" in value or "id_rsa" in value or "id_ed25519" in value \
            or "id_ecdsa" in value or "id_dsa" in value:
        add("SSH_CREDENTIAL_READ", rel, line)
    if ".aws" in value or ".azure" in value or ".gcloud" in value:
        add("CLOUD_CREDENTIAL_READ", rel, line)
    if (value.rstrip("/").endswith(".env") or "/.env" in value or value == ".env") \
            and not _PLACEHOLDER_ENV_RE.search(value):
        add("ENV_FILE_READ", rel, line)
    if any(fragment in value for fragment in _BROWSER_STORE_FRAGMENTS):
        add("BROWSER_CREDENTIAL_STORE", rel, line)


def _is_metadata_text(text: str) -> bool:
    """True if the text references a cloud metadata endpoint, in any of
    the forms the CLOUD_METADATA_ACCESS rule recognises."""
    return bool(RULES_BY_ID["CLOUD_METADATA_ACCESS"].pattern.search(text))


def _call_strings(node: ast.Call, sym: _Symbols) -> list[str]:
    """All constant-folded strings among a call's args and keyword values."""
    out: list[str] = []
    for arg in list(node.args) + [kw.value for kw in node.keywords]:
        folded = _fold_str(arg, sym)
        if folded:
            out.append(folded)
        lst = _fold_list(arg, sym)
        if lst:
            out.extend(str(i) for i in lst)
    return out


def _ast_findings(path: Path, rel: str, text: str, add, flags: dict) -> set[int]:
    """AST checks for one Python file. `flags` is the SCAN-scoped dict —
    only the "send" flag is allowed to merge outward into it (a send in
    any file is a send channel for the whole skill). decode / run_sink /
    urllib_send are PER-FILE: they live in a local dict, because a decode
    in a.py plus an eval in b.py is not a decode-and-run dropper, and a
    urllib Request(data=...) in a.py does not make a plain urlopen() in
    b.py a send. Returns the set of line numbers whose send call's
    destination is a cloud metadata endpoint itself (the IMDSv2 token
    PUT shape) — those are metadata access, not exfiltration, and the
    line-rule pass must not count them as sends either."""
    metadata_send_lines: set[int] = set()
    try:
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return metadata_send_lines
    sym = _Symbols()
    _collect_symbols(tree, sym)
    local: dict = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is not None:
                folded = _fold_str(value, sym)
                if folded:
                    _check_credential_value(folded, rel, node.lineno, add)
            continue
        if isinstance(node, ast.Subscript):
            if _resolve(node.value, sym) == "os.environ":
                add("ENVIRON_SECRET_ACCESS", rel, node.lineno)
            continue
        if isinstance(node, ast.Attribute):
            if _resolve(node, sym) == "os.environ":
                add("ENVIRON_SECRET_ACCESS", rel, node.lineno)
            continue
        if not isinstance(node, ast.Call):
            continue

        line = node.lineno
        dotted = _resolve(node.func, sym)
        raw = _raw_dotted(node.func)

        # Dynamic loading that cannot be resolved is itself a finding.
        # (Plain getattr(obj, "attr") on ordinary objects is NOT flagged —
        # it is ubiquitous benign Python. getattr() dispatch onto a module
        # is resolved above and produces the real behaviour's finding.)
        if raw in ("importlib.import_module", "import_module"):
            if not node.args or _fold_str(node.args[0], sym) is None:
                add("DYNAMIC_IMPORT", rel, line)
        if raw in ("importlib.import_module", "import_module") and node.args:
            folded_mod = _fold_str(node.args[0], sym)
            if folded_mod in ("subprocess", "os", "shutil", "socket", "requests", "httpx"):
                add("DYNAMIC_IMPORT", rel, line)
            if folded_mod and ("base64" in folded_mod or "binascii" in folded_mod):
                local["decode"] = (rel, line)

        if dotted in _AST_CALL_RULES:
            add(_AST_CALL_RULES[dotted], rel, line)

        module = dotted.split(".")[0] if dotted else ""
        method = dotted.rsplit(".", 1)[-1] if dotted else ""

        # A send whose destination IS a cloud metadata endpoint (the
        # IMDSv2 token PUT, a metadata POST) is metadata access — the
        # CLOUD_METADATA_ACCESS finding covers it — not an outbound send:
        # it must not produce NETWORK_SEND_DATA nor count as the "send"
        # half of any combination rule.
        dest_is_metadata = any(
            _is_metadata_text(s) for s in _call_strings(node, sym))

        # HTTP client calls (alias-resolved).
        if module in ("requests", "httpx"):
            if method in _SEND_METHODS:
                if dest_is_metadata:
                    metadata_send_lines.add(line)
                    add("NETWORK_ACCESS", rel, line)
                else:
                    add("NETWORK_SEND_DATA", rel, line)
                    flags["send"] = (rel, line)
            elif method in ("get", "head", "request"):
                kw_names = {kw.arg for kw in node.keywords}
                if "params" in kw_names or "data" in kw_names:
                    if dest_is_metadata:
                        metadata_send_lines.add(line)
                        add("NETWORK_ACCESS", rel, line)
                    else:
                        add("NETWORK_SEND_DATA", rel, line)
                        flags["send"] = (rel, line)
                else:
                    add("NETWORK_ACCESS", rel, line)
            else:
                add("NETWORK_ACCESS", rel, line)
        elif dotted.startswith("urllib"):
            add("NETWORK_ACCESS", rel, line)
            if method == "Request":
                kw_names = {kw.arg for kw in node.keywords}
                if "data" in kw_names or len(node.args) >= 2:
                    local["urllib_send"] = (rel, line)
            if method == "urlopen" and "urllib_send" in local:
                url_folded = _fold_str(node.args[0], sym) if node.args else None
                if url_folded and _is_metadata_text(url_folded):
                    metadata_send_lines.add(line)
                else:
                    add("NETWORK_SEND_DATA", rel, line)
                    flags["send"] = (rel, line)
        elif dotted.startswith("http.client"):
            add("NETWORK_ACCESS", rel, line)
            if method in ("request", "putrequest"):
                kw_names = {kw.arg for kw in node.keywords}
                if "body" in kw_names or len(node.args) >= 4:
                    if dest_is_metadata:
                        metadata_send_lines.add(line)
                    else:
                        add("NETWORK_SEND_DATA", rel, line)
                        flags["send"] = (rel, line)

        # Raw socket sends (send / sendall / sendto on ANY receiver) are
        # network access, never a send finding on their own: chat clients
        # and echo servers are ordinary benign socket code, and the old
        # variable-name heuristic ("sock" in the name) blocked them while
        # missing renamed stealers. A send on a receiver that resolves to
        # the socket module still counts as a send CHANNEL for the
        # combination rules (credential read + any send is the exfil
        # shape) via the scan-scoped flag — resolution is by import /
        # assignment tracking, never by variable name.
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("send", "sendall", "sendto"):
            add("NETWORK_ACCESS", rel, line)
            if dotted.startswith("socket"):
                flags["send"] = (rel, line)

        # subprocess: inspect folded arguments for curl-style exfil / cat of keys.
        if dotted.startswith("subprocess."):
            add("SHELL_SUBPROCESS", rel, line)
            pieces: list[str] = []
            for arg in node.args:
                folded = _fold_str(arg, sym)
                if folded:
                    pieces.append(folded)
                lst = _fold_list(arg, sym)
                if lst:
                    pieces.extend(str(i) for i in lst)
            joined = " ".join(pieces)
            if ("curl" in joined or "wget" in joined) and any(
                    t in joined for t in ("-d", "--data", "--post-data", "@")):
                if _is_metadata_text(joined):
                    metadata_send_lines.add(line)
                else:
                    add("NETWORK_SEND_DATA", rel, line)
                    flags["send"] = (rel, line)
            if joined:
                _check_credential_value(joined, rel, line, add)

        # Decode-class calls (for DECODE_AND_RUN co-occurrence — strictly
        # within THIS file; see the local flags note above).
        if module in ("base64", "binascii") or method in ("b64decode", "a2b_base64", "fromhex"):
            local["decode"] = (rel, line)
        if dotted in ("eval", "exec", "__import__") or raw in (
                "importlib.import_module", "import_module") or dotted.startswith("subprocess."):
            local.setdefault("run_sink", (rel, line))

        # Credential values in any folded call argument.
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            folded = _fold_str(arg, sym)
            if folded:
                _check_credential_value(folded, rel, line, add)
            lst = _fold_list(arg, sym)
            if lst:
                _check_credential_value(" ".join(str(i) for i in lst), rel, line, add)
            # A constructor like Path(home, ".s"+"sh", "id_"+"rsa"): join args.
        if node.args and len(node.args) >= 2:
            folded_parts = [_fold_str(a, sym) for a in node.args]
            if all(p is not None for p in folded_parts):
                _check_credential_value("/".join(folded_parts), rel, line, add)

        # Credential enumeration via glob on home-shaped targets.
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("glob", "rglob"):
            for arg in node.args:
                folded = _fold_str(arg, sym)
                if folded and ("id_" in folded or ".ssh" in folded or "*key" in folded):
                    add("CREDENTIAL_ENUMERATION", rel, line)
                    if ".ssh" in folded:
                        add("SSH_CREDENTIAL_READ", rel, line)

    # Error / environment leakage into tool results: a `return` inside an
    # except block that hands back the exception itself (str(e),
    # f"...{e}", the bare name, format_exc()) — or any return of the whole
    # environment — ships internal detail to whoever called the tool.
    # Logging the exception and returning a plain message does NOT match:
    # only Return nodes are inspected.
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            exc_name = node.name
            # One-hop locals: `tb = traceback.format_exc()` or
            # `msg = str(e)` assigned inside the handler and then
            # returned leaks exactly like returning the call directly.
            leak_vars: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and len(sub.targets) == 1 \
                        and isinstance(sub.targets[0], ast.Name) \
                        and isinstance(sub.value, ast.Call):
                    raw = _raw_dotted(sub.value.func)
                    if raw in ("traceback.format_exc", "format_exc"):
                        leak_vars.add(sub.targets[0].id)
                    elif exc_name and raw == "str" and sub.value.args \
                            and isinstance(sub.value.args[0], ast.Name) \
                            and sub.value.args[0].id == exc_name:
                        leak_vars.add(sub.targets[0].id)
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Return) or sub.value is None:
                    continue
                leaked = False
                for part in ast.walk(sub.value):
                    if isinstance(part, ast.Call):
                        raw = _raw_dotted(part.func)
                        if raw in ("traceback.format_exc", "format_exc"):
                            leaked = True
                        if exc_name and raw == "str" and part.args \
                                and isinstance(part.args[0], ast.Name) \
                                and part.args[0].id == exc_name:
                            leaked = True
                    elif isinstance(part, ast.Name) and (
                            (exc_name and part.id == exc_name)
                            or part.id in leak_vars):
                        leaked = True
                    elif _resolve(part, sym) == "os.environ" and isinstance(
                            part, (ast.Attribute, ast.Name, ast.Call)):
                        leaked = True
                if leaked:
                    add("ERROR_INFO_LEAK", rel, sub.lineno)
        elif isinstance(node, ast.Return) and node.value is not None:
            for part in ast.walk(node.value):
                if _resolve(part, sym) == "os.environ" and isinstance(
                        part, (ast.Attribute, ast.Call)):
                    add("ERROR_INFO_LEAK", rel, node.lineno)
                    break

    if "decode" in local and "run_sink" in local:
        rel_d, line_d = local["decode"]
        add("DECODE_AND_RUN", rel_d, line_d)
    return metadata_send_lines


# --------------------------------------------------------------------------
# Shell scripts: simple variable expansion before line rules
# --------------------------------------------------------------------------

_SH_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=([\"']?)([^\n\"']*)\2\s*$")
_SH_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def _expand_shell_lines(lines: list[str]) -> list[str]:
    env: dict[str, str] = {}
    out = []
    for line in lines:
        m = _SH_ASSIGN_RE.match(line)
        if m:
            env[m.group(1)] = _SH_VAR_RE.sub(lambda mm: env.get(mm.group(1), mm.group(0)), m.group(3))
        out.append(_SH_VAR_RE.sub(lambda mm: env.get(mm.group(1), mm.group(0)), line))
    return out


# --------------------------------------------------------------------------
# JSON / MCP manifests: structural rules
# --------------------------------------------------------------------------

_EXEC_TOOL_RE = re.compile(r"(run|exec|execut|shell|command|system|terminal|bash|code)", re.IGNORECASE)
_READ_TOOL_RE = re.compile(r"(read|file|path|cat|load)", re.IGNORECASE)
_SHELL_COMMANDS = {
    "bash", "sh", "zsh", "cmd", "powershell", "pwsh", "python", "python3",
    "node", "npx", "uvx", "deno", "bun", "ruby", "perl",
}


def _find_line(lines: list[str], needle: str) -> int:
    for i, text in enumerate(lines, start=1):
        if needle and needle in text:
            return i
    return 1


def _manifest_findings(rel: str, text: str, lines: list[str], add, note=None) -> None:
    try:
        data = json.loads(text)
    except Exception:
        # A malformed JSON file cannot be structurally analysed. Its
        # text was still line-scanned, but the coverage gap must be
        # surfaced (SCAN_INCOMPLETE), never silently treated as clean.
        if note is not None:
            note(Skipped(rel, "malformed JSON — manifest analysis skipped", True))
        return
    if not isinstance(data, dict):
        return

    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            command = cfg.get("command")
            if isinstance(command, str):
                base = command.replace("\\", "/").rstrip("/").split("/")[-1].lower()
                if base in _SHELL_COMMANDS or base.endswith(".exe") and base[:-4] in _SHELL_COMMANDS:
                    add("MCP_SERVER_COMMAND", rel, _find_line(lines, command))
            env = cfg.get("env")
            if isinstance(env, dict):
                for key in env:
                    if SECRET_NAME_RE.search(str(key)):
                        add("ENVIRON_SECRET_ACCESS", rel, _find_line(lines, str(key)))

    tools = data.get("tools")
    if isinstance(tools, list):
        has_exec = False
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            blob = f"{tool.get('name', '')} {tool.get('description', '')}"
            schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            free_string = any(
                isinstance(p, dict) and p.get("type") == "string" and "enum" not in p
                for p in props.values()
            )
            line = _find_line(lines, str(tool.get("name", "")))
            if free_string and _EXEC_TOOL_RE.search(blob):
                add("MCP_UNRESTRICTED_EXEC", rel, line)
                has_exec = True
            if free_string and _READ_TOOL_RE.search(blob) and any(
                    "path" in str(k).lower() or "file" in str(k).lower() for k in props):
                add("MCP_UNRESTRICTED_READ", rel, line)
        _ = has_exec


# --------------------------------------------------------------------------
# Hardcoded secrets (S8): format-anchored live tokens + generic entropy
# --------------------------------------------------------------------------
#
# Two tiers, deliberately:
#  * LIVE (block): formats that are unambiguous when they appear in full —
#    an AWS access-key id, a GitHub token, an sk- API key, a Slack token,
#    a PEM private-key header. There is no innocent reason for a complete
#    live-format credential to sit in installable code, so these block.
#  * GENERIC (caution): a long, high-entropy literal assigned to a
#    password/secret/token variable. Plenty of these are innocent test
#    values, so this tier only cautions.
# Both tiers suppress obvious placeholders ("your-api-key", "xxxx",
# "example", "changeme", …), values that are really references
# (os.environ[...], ${VAR}, {{ template }}), and documentation lines
# clearly marked as examples. Suppression is substring-based and
# conservative: it can only ever *reduce* findings, and a placeholder
# word inside a random-looking token is unlikely by construction.

_LIVE_SECRET_RES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                                # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),                      # GitHub classic tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),                    # GitHub fine-grained PAT
    re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}"),                       # Anthropic API key
    re.compile(r"sk-proj-[A-Za-z0-9_-]{16,}"),                      # OpenAI project key
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{32,}"),             # OpenAI legacy key
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),                     # Slack token
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),                           # Google API key
    re.compile(r"[sr]k_live_[A-Za-z0-9]{16,}"),                     # Stripe live secret/restricted key
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),                        # GitLab personal access token
    re.compile(r"npm_[A-Za-z0-9]{36}"),                             # npm access token
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
]
# Formats that are unambiguous but NOT live credentials (test-mode keys):
# they belong to the generic (caution) tier when they appear in code.
_GENERIC_FORMAT_RES = [
    re.compile(r"[sr]k_test_[A-Za-z0-9]{16,}"),                     # Stripe test keys
]
_PLACEHOLDER_MARKERS = (
    "example", "sample", "dummy", "fake", "placeholder", "changeme",
    "change-me", "redacted", "your-", "your_", "your api", "xxxx",
    "****", "insert", "replace-me", "replace_me", "todo", "<your",
    "not-a-real", "not_a_real", "mock",
)
_REFERENCE_MARKERS = (
    "os.environ", "environ[", "environ.get", "getenv", "process.env",
    "${", "{{", "}}", "<", ">", "config(", "settings.", "vault",
    "keyring", "secretmanager", "secretsmanager",
)
_GENERIC_SECRET_RE = re.compile(
    # Variable names: a secret-ish word anywhere in the name (dev_token,
    # api_key, session_secret) — but the name must END at the secret-ish
    # word, so "tokenizer" and "secretary" do not match.
    r"(?i)(?:^|[^\w])([A-Za-z0-9_]*?(?:password|passwd|pwd|secret|token|"
    r"api[_-]?key|client[_-]?secret|private[_-]?key))\s*[:=]\s*"
    r"[\"']([^\"'\s]{8,})[\"']"
)
_ENV_STYLE_SECRET_RE = re.compile(
    r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(PASSWORD|PASSWD|SECRET|API[_-]?KEY|"
    r"ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET)[A-Z0-9_]*\s*=\s*"
    r"[\"']?([^\s\"'#]{8,})[\"']?\s*$"
)
# A bare secret-ish name as the WHOLE name (KEY, TOKEN, SECRET, PASSWORD)
# also qualifies for the generic tier when the value is high-entropy.
# The word-boundary anchors keep "monkey" / "turnkey" / "keyboard" out.
_GENERIC_BARE_NAME_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(KEY|TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|"
    r"API_KEY|CLIENT_SECRET)(?![A-Za-z0-9_])\s*[:=]\s*"
    r"[\"']([^\"'\s]{8,})[\"']"
)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    if any(m in low for m in _PLACEHOLDER_MARKERS):
        return True
    if any(m in low for m in _REFERENCE_MARKERS):
        return True
    # A single repeated character or two-character cycle is not a secret.
    return len(set(value)) <= 2


_FAKE_MARK_RE = re.compile(r"\b(fake|fixture)\b|FAKE_|FIXTURE", re.IGNORECASE)


def _secret_findings(rel: str, path: Path, lines: list[str], doc: bool, add) -> None:
    # Placeholder env templates (.env.example and friends) are templates
    # by design: the env-style generic check does not apply to them.
    placeholder_env = bool(_PLACEHOLDER_ENV_RE.search(path.name))
    env_style = (path.name.startswith(".env") and not placeholder_env) \
        or path.suffix.lower() in (".ini", ".cfg", ".toml")
    # Test-fixture context: a live-format value inside tests, in a
    # test_*.py / conftest.py file, or next to an explicit FAKE_ /
    # FIXTURE marker is test data, not a shipped credential. It is
    # still reported — downgraded to CAUTION, never suppressed.
    rel_parts = Path(rel).parts
    test_context = (
        any(part.lower() in ("tests", "test") for part in rel_parts[:-1])
        or (path.name.startswith("test_") and path.suffix == ".py")
        or path.name == "conftest.py"
        or path.name.endswith("_test.py")
    )
    for lineno, line in enumerate(lines, start=1):
        low = line.lower()
        if doc and "example" in low:
            # Documentation examples clearly marked as examples are not
            # findings (spec requirement), in either tier.
            continue
        fake_marked = bool(_FAKE_MARK_RE.search(line)) or (
            lineno >= 2 and bool(_FAKE_MARK_RE.search(lines[lineno - 2])))
        live_cap = "caution" if (doc or test_context or fake_marked) else None
        live_hit = False
        for pattern in _LIVE_SECRET_RES:
            m = pattern.search(line)
            if m and not _looks_placeholder(m.group(0)):
                add("HARDCODED_SECRET_LIVE", rel, lineno, line,
                    severity_cap=live_cap)
                live_hit = True
                break
        if live_hit:
            continue  # one secret finding per line is enough
        generic = _GENERIC_SECRET_RE.search(line)
        if generic is None:
            generic = _GENERIC_BARE_NAME_RE.search(line)
        if generic is None and env_style:
            generic = _ENV_STYLE_SECRET_RE.search(line)
        generic_hit = False
        if generic is not None:
            value = generic.group(2)
            if not _looks_placeholder(value) and _entropy(value) >= 3.5 \
                    and len(set(value)) >= 6:
                generic_hit = True
        if not generic_hit:
            # Test-mode formats (Stripe sk_test_ etc.) are generic-tier.
            generic_hit = any(
                p.search(line) and not _looks_placeholder(p.search(line).group(0))
                for p in _GENERIC_FORMAT_RES)
        if generic_hit:
            add("HARDCODED_SECRET_GENERIC", rel, lineno, line,
                severity_cap="caution" if doc else None)


# --------------------------------------------------------------------------
# Raw-socket reverse shell: socket + shell wiring in the same file
# --------------------------------------------------------------------------

_SOCKET_RE = re.compile(
    r"(socket\.socket|create_connection|net\.connect|net\.Socket|/dev/tcp/|"
    r"TCPSocket|Socket\.tcp)")
_SHELL_WIRE_RES = [
    re.compile(r"\bdup2\s*\("),                       # socket fd -> stdin/out/err
    re.compile(r"pty\.spawn"),                        # spawn a pty shell
    re.compile(r"/dev/tcp/"),                         # bash built-in socket
    re.compile(r"IO\.popen\s*\("),                    # Ruby: popen a shell per line read
    re.compile(r"(subprocess\.|child_process|os\.system|execSync|spawn\s*\()"
               r"[^\n]{0,120}(/bin/(ba)?sh|\bsh\b['\"]?\s*[,\)\]]|cmd\.exe)"),
]


def _reverse_shell_findings(rel: str, text: str, lines: list[str], add) -> None:
    if not _SOCKET_RE.search(text):
        return  # a shell with no socket is SHELL_* territory, not this rule
    for pattern in _SHELL_WIRE_RES:
        m = pattern.search(text)
        if m:
            line_no = text[:m.start()].count("\n") + 1
            evidence = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            add("REVERSE_SHELL", rel, line_no, evidence)
            return


# --------------------------------------------------------------------------
# Package manifests: npm lifecycle scripts and setup.py behaviour
# --------------------------------------------------------------------------

_NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
# Download/execute verbs for install-time scripts. A bare URL is NOT
# enough (a docs link in a script argument is not a download): a fetch
# or execute verb must be associated with the command.
_INSTALL_EXEC_RE = re.compile(
    r"(curl\b|wget\b|\|\s*(sudo\s+)?(bash|sh|zsh)\b|base64\b|/dev/tcp/|"
    r"\bnc\s|powershell|certutil|\bfetch\b|\bdownload\b|aria2c|"
    r"Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)",
    re.IGNORECASE)
_SETUP_BEHAVIOUR_RE = re.compile(
    r"(subprocess|os\.system|os\.popen|urllib|requests|httpx|socket|"
    r"check_output|check_call)")
# Exact well-known benign lifecycle commands: building a native addon
# with node-gyp, and husky's git-hook setup. These run on millions of
# benign installs; flagging them teaches users to ignore the rule.
_BENIGN_LIFECYCLE_RES = [
    re.compile(r"^node-gyp\s+rebuild(\s+--?[A-Za-z][\w-]*)*\s*$"),
    re.compile(r"^husky(\s+install)?\s*$"),
]
# Patterns for a lifecycle-referenced local JS file: fetching code and
# executing/spawning something are each common alone (a downloader, a
# build runner); together in an install-referenced file they are the
# download-and-run shape.
_JS_FETCH_RE = re.compile(
    r"(https?\.get\b|https?\.request\b|fetch\s*\(|axios|got\s*\(|undici|"
    r"XMLHttpRequest|curl\b|wget\b)")
_JS_EXEC_RE = re.compile(
    r"(child_process|exec\s*\(|execFile|execSync|spawn\s*\(|spawnSync)")
_NODE_FILE_RE = re.compile(r"(?:^|\s)node\s+(\S+\.(?:mjs|cjs|js))\b")
_SETUP_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)


def _strip_py_comments(text: str) -> str:
    """Blank out Python comments (positions preserved) so behaviour
    regexes match code, not prose about code. Falls back to the raw
    text when the file cannot be tokenised."""
    lines = text.splitlines()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                row, col = tok.start
                if 0 < row <= len(lines):
                    lines[row - 1] = lines[row - 1][:col]
    except Exception:
        return text
    return "\n".join(lines)


def _referenced_js_exec(pkg_dir: Path, root: Path, command: str) -> bool:
    """One level of npm indirection: a lifecycle script like
    `node scripts/setup.js` runs that file at install time, so the file
    is checked for the fetch+execute shape. The reference must resolve
    to an existing file INSIDE the scanned folder."""
    m = _NODE_FILE_RE.search(command)
    if not m:
        return False
    ref = m.group(1).strip("\"'")
    if os.path.isabs(ref):
        return False
    try:
        target = (pkg_dir / ref).resolve()
        target.relative_to(root.resolve())
        if not target.is_file():
            return False
        text = target.read_bytes()[:MAX_FILE_BYTES]
        decoded = _decode(text)
    except (OSError, ValueError):
        return False
    if decoded is None:
        return False
    return bool(_JS_FETCH_RE.search(decoded) and _JS_EXEC_RE.search(decoded))


def _package_findings(rel: str, path: Path, text: str, lines: list[str],
                      add, root: Path, note=None) -> None:
    if path.name == "package.json":
        try:
            data = json.loads(text)
        except Exception:
            if note is not None:
                note(Skipped(rel, "malformed package.json — "
                                  "install-script analysis skipped", True))
            return
        if not isinstance(data, dict):
            return
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            return
        for key in _NPM_LIFECYCLE:
            command = scripts.get(key)
            if not isinstance(command, str) or not command.strip():
                continue
            if any(p.match(command.strip()) for p in _BENIGN_LIFECYCLE_RES):
                continue  # node-gyp rebuild / husky: standard, benign
            line = _find_line(lines, f'"{key}"')
            add("PACKAGE_INSTALL_SCRIPT", rel, line, command)
            if _INSTALL_EXEC_RE.search(command) or _referenced_js_exec(
                    path.parent, root, command):
                add("PACKAGE_INSTALL_SCRIPT_EXEC", rel, line, command)
    elif path.name == "setup.py":
        # setup.py is EXECUTED by pip at install/build time. A setup.py
        # that only declares metadata is fine; one reaching for
        # subprocess/network/sockets is install-time code execution.
        # Comments are stripped first: prose about subprocess is not
        # subprocess. The same behaviour check is applied ONE LEVEL deep
        # to local modules setup.py imports, since the payload commonly
        # sits in the imported file.
        code = _strip_py_comments(text)
        hit_line = None
        for lineno, line in enumerate(code.splitlines(), start=1):
            if _SETUP_BEHAVIOUR_RE.search(line):
                hit_line = lineno
                break
        if hit_line is None:
            for m in _SETUP_IMPORT_RE.finditer(code):
                module_file = path.parent / f"{m.group(1)}.py"
                if not module_file.is_file():
                    continue
                try:
                    module_text = _decode(
                        module_file.read_bytes()[:MAX_FILE_BYTES])
                except OSError:
                    continue
                if module_text is not None and _SETUP_BEHAVIOUR_RE.search(
                        _strip_py_comments(module_text)):
                    hit_line = code[:m.start()].count("\n") + 1
                    break
        if hit_line is not None:
            evidence = lines[hit_line - 1] if 0 < hit_line <= len(lines) else ""
            add("PACKAGE_INSTALL_SCRIPT", rel, hit_line, evidence)


# --------------------------------------------------------------------------
# Main scan
# --------------------------------------------------------------------------

def scan_folder(root: Path) -> ScanResult:
    root = root.resolve()
    result = ScanResult(target=str(root))
    index: dict[tuple[str, str], Finding] = {}
    flags: dict = {}
    send_at: tuple[str, int] | None = None
    cred_at: tuple[str, int] | None = None
    metadata_at: tuple[str, int] | None = None

    def add(rule_id: str, rel: str, line: int, evidence: str = "", severity_cap: str | None = None) -> None:
        nonlocal send_at, cred_at, metadata_at
        rule = RULES_BY_ID[rule_id]
        severity = rule.severity
        if severity_cap == "caution" and severity == "block":
            severity = "caution"
        key = (rule_id, rel)
        existing = index.get(key)
        if existing is not None:
            existing.count += 1
            if not existing.evidence and evidence:
                # First hit wins the slot, but an evidence-free hit
                # (e.g. an AST finding) must not swallow the evidence
                # of a later hit on the same rule+file.
                existing.evidence = evidence.strip()[:160]
            return
        finding = Finding(rule=rule_id, severity=severity, file=rel, line=line,
                          reason=rule.reason, evidence=evidence.strip()[:160])
        index[key] = finding
        result.findings.append(finding)
        if rule_id in CREDENTIAL_RULES and cred_at is None:
            cred_at = (rel, line)
        if rule_id in SEND_RULES and send_at is None:
            send_at = (rel, line)
        if rule_id == "CLOUD_METADATA_ACCESS" and metadata_at is None:
            metadata_at = (rel, line)

    files_seen = 0
    total_bytes = 0
    for path in _iter_files(root, result.skipped):
        rel = str(path.relative_to(root))
        suffix = path.suffix.lower()
        files_seen += 1
        if files_seen > MAX_TOTAL_FILES or total_bytes > MAX_TOTAL_BYTES:
            result.skipped.append(Skipped(
                rel,
                f"scan budget exceeded (>{MAX_TOTAL_FILES} files or "
                f">{MAX_TOTAL_BYTES} bytes total) — scan stopped early",
                True))
            break
        try:
            raw = path.read_bytes()
        except OSError:
            result.skipped.append(Skipped(rel, "unreadable", True))
            continue
        total_bytes += len(raw)
        if len(raw) > MAX_FILE_BYTES:
            result.skipped.append(Skipped(rel, f"over size cap ({len(raw)} bytes)", True))
            continue
        text = _decode(raw)
        if text is None:
            suspicious = suffix in TEXTLIKE_EXTENSIONS
            result.skipped.append(Skipped(rel, "binary-looking content", suspicious))
            continue
        result.scanned_files += 1
        lines = text.splitlines()
        doc = _is_doc(path)

        # Structural manifest rules for JSON. A hostile manifest must never
        # crash the scan — a failure here degrades to a coverage note.
        if suffix == ".json":
            try:
                _manifest_findings(rel, text, lines, add,
                                   note=result.skipped.append)
            except Exception:
                result.skipped.append(Skipped(rel, "manifest analysis failed", True))

        # Python AST first: it identifies sends whose destination is a
        # cloud metadata endpoint itself, and the line pass below must
        # not count those as sends (FP2).
        metadata_send_lines: set[int] = set()
        if suffix == ".py":
            try:
                metadata_send_lines = _ast_findings(path, rel, text, add, flags)
            except Exception:
                # Deeply nested / pathological syntax trees can defeat the
                # AST analyser (e.g. recursion limits). Line rules below
                # still run; record the gap instead of crashing.
                result.skipped.append(Skipped(rel, "python AST analysis failed", True))

        # Line rules (shell files get variable expansion first).
        scan_lines = _expand_shell_lines(lines) if suffix in (".sh", ".bash", ".zsh") else lines
        for lineno, line_text in enumerate(scan_lines, start=1):
            if doc and NEGATION_RE.search(line_text):
                # Documentation that warns AGAINST a pattern ("never reads
                # ~/.ssh") is safety documentation, not behaviour.
                continue
            stripped = line_text.lstrip()
            for rule in LINE_RULES:
                if doc and rule.id in ("NETWORK_ACCESS", "ENV_FILE_READ",
                                       "CLOUD_METADATA_ACCESS"):
                    # Prose is not behaviour: hyperlinks are not network
                    # code, and a doc mentioning a .env file or a metadata
                    # address does not read or reach one.
                    continue
                if rule.id == "NETWORK_SEND_DATA" and (
                        lineno in metadata_send_lines
                        or _is_metadata_text(line_text)):
                    # A send TO the metadata endpoint itself is metadata
                    # access (caution), not an outbound send.
                    continue
                if rule.id == "ENV_FILE_READ" and stripped.startswith(("#", "//")):
                    # A comment mentioning .env is prose, not a read.
                    continue
                if rule.pattern.search(line_text[:MAX_LINE_CHARS]):
                    add(rule.id, rel, lineno, lines[lineno - 1] if lineno - 1 < len(lines) else line_text,
                        severity_cap="caution" if doc else None)

        if suffix in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
            # Squeeze adjacent string-literal concatenations ("id_" + "rsa"
            # -> "id_rsa") and re-run line rules on the squeezed text.
            squeezed = [
                re.sub(r"([\"'])\s*\+\s*([\"'])", "", line_text)
                for line_text in lines
            ]
            for lineno, line_text in enumerate(squeezed, start=1):
                for rule in LINE_RULES:
                    if rule.pattern.search(line_text[:MAX_LINE_CHARS]):
                        add(rule.id, rel, lineno, lines[lineno - 1])
            # fetch(url, {method: "POST", body}) spanning lines.
            if "fetch(" in text and re.search(
                    r"method\s*:\s*[\"'](POST|PUT|PATCH)[\"']", text):
                for lineno, line_text in enumerate(lines, start=1):
                    if "fetch(" in line_text:
                        add("NETWORK_SEND_DATA", rel, lineno, line_text)
                        flags["send"] = (rel, lineno)
                        break

        # File-level: encoded payload + dynamic execution in the same file
        # (substring fallback; the AST class check above is the primary path).
        lowered = text.lower()
        decode_hit = any(t in lowered for t in ("b64decode", "base64", "a2b_base64", "fromhex"))
        run_hit = any(t in lowered for t in ("eval(", "exec(", "__import__", "import_module"))
        if decode_hit and run_hit:
            for lineno, line_text in enumerate(lines, start=1):
                if "b64decode" in line_text.lower() or "base64" in line_text.lower():
                    add("DECODE_AND_RUN", rel, lineno, line_text,
                        severity_cap="caution" if doc else None)
                    break

        # Dedicated matchers (not line regexes): hardcoded secrets,
        # raw-socket reverse shells, package install-time behaviour.
        # Hostile input must never crash the scan — failures here degrade
        # to a coverage note, like manifest analysis above.
        try:
            _secret_findings(rel, path, lines, doc, add)
            _reverse_shell_findings(rel, text, lines, add)
            _package_findings(rel, path, text, lines, add, root,
                              note=result.skipped.append)
        except Exception:
            result.skipped.append(Skipped(rel, "extended analysis failed", True))

        if "send" in flags and send_at is None:
            send_at = flags["send"]

    # Scan-level combination: credential access + a send channel anywhere in
    # the same skill is the exfiltration shape.
    if cred_at is not None and (send_at is not None or "send" in flags):
        at = send_at or flags.get("send") or cred_at
        add("EXFIL_COMBINATION", at[0], at[1])

    # Cloud metadata endpoints hand out live credentials: touching one is
    # a caution alone, but metadata access combined with a send channel
    # or other credential access is the cloud credential-theft shape.
    if metadata_at is not None and (
            send_at is not None or "send" in flags or cred_at is not None):
        add("CLOUD_METADATA_EXFIL", metadata_at[0], metadata_at[1])

    # Coverage honesty: suspicious skips (or scanning nothing at all) must
    # stop the folder from reading as a clean PASS.
    suspicious_skips = [s for s in result.skipped if s.suspicious]
    if suspicious_skips or result.scanned_files == 0:
        first = suspicious_skips[0].file if suspicious_skips else "."
        add("SCAN_INCOMPLETE", first, 0)

    result.findings.sort(key=lambda f: (f.file, f.line, f.rule))
    severities = {f.severity for f in result.findings}
    if "block" in severities:
        result.verdict = "BLOCK"
    elif "caution" in severities:
        result.verdict = "CAUTION"
    else:
        result.verdict = "PASS"
    return result
