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
                    "owasp": RULES_BY_ID[f.rule].owasp,
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
        self.attr_obj: dict[str, str] = {}     # "self.session" -> module of object it was built from
        self.env_str: dict[str, str] = {}      # var -> folded string value
        self.env_list: dict[str, list] = {}    # var -> folded list value
        # Every module a name (or attribute) was EVER bound to in this
        # file. A name bound to two different modules in different
        # scopes is AMBIGUOUS: the flat table cannot tell which binding
        # a given call site sees, so at the end of collection such
        # names are dropped from var_obj / attr_obj rather than guessed
        # (a wrong guess manufactures both false positives — a foreign
        # client's .post read as a session send — and false negatives).
        self.obj_candidates: dict[str, set] = {}
        self.attr_candidates: dict[str, set] = {}


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
    # Attribute-rooted bindings ("self.session.post"): the longest
    # attribute prefix bound to a constructed object wins, so a
    # session stored on an instance resolves exactly like a variable.
    parts = raw.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in sym.attr_obj:
            return sym.attr_obj[prefix] + "." + ".".join(parts[i:])
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
    def note_var(name: str, ctor: str) -> None:
        """Record a name -> constructed-object binding, keeping every
        candidate module for the ambiguity purge at the end."""
        module = ctor.rsplit(".", 1)[0] if "." in ctor else ""
        if module:
            sym.var_obj[name] = module
            sym.obj_candidates.setdefault(name, set()).add(module)

    def note_attr(dotted: str, ctor: str) -> None:
        module = ctor.rsplit(".", 1)[0] if "." in ctor else ""
        if module:
            sym.attr_obj[dotted] = module
            sym.attr_candidates.setdefault(dotted, set()).add(module)

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
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            # `with requests.Session() as s:` / `async with
            # aiohttp.ClientSession() as s:` binds the constructed
            # object exactly like an assignment — without this,
            # session/client sends through the bound name were
            # invisible to the call analysis.
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name) \
                        and isinstance(item.context_expr, ast.Call):
                    note_var(item.optional_vars.id,
                             _resolve(item.context_expr.func, sym))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                continue
            for target in targets:
                # Attribute targets rooted at a name (`self.session =
                # requests.Session()`) bind an object exactly like a
                # variable does; track them under their dotted path so
                # `self.session.post(...)` resolves as a session send,
                # identically to the variable-bound form.
                attr_dotted = ""
                if isinstance(target, ast.Attribute):
                    attr_dotted = _raw_dotted(target)
                    if not attr_dotted:
                        continue
                elif not isinstance(target, ast.Name):
                    continue
                name = target.id if isinstance(target, ast.Name) else ""
                if isinstance(value, ast.Call):
                    raw = _raw_dotted(value.func)
                    resolved_ctor = _resolve(value.func, sym)
                    if resolved_ctor:
                        if attr_dotted:
                            note_attr(attr_dotted, resolved_ctor)
                        else:
                            note_var(name, resolved_ctor)
                    if raw in ("importlib.import_module", "import_module") and value.args:
                        folded = _fold_str(value.args[0], sym)
                        if folded and not attr_dotted:
                            sym.var_module[name] = folded
                        continue
                    if raw == "getattr" and len(value.args) >= 2:
                        resolved = _resolve(value, sym)
                        if resolved and not attr_dotted:
                            sym.var_callable[name] = resolved
                        continue
                if attr_dotted:
                    continue  # folded strings/lists are name-keyed only
                folded = _fold_str(value, sym)
                if folded is not None:
                    sym.env_str[name] = folded
                    continue
                lst = _fold_list(value, sym)
                if lst is not None:
                    sym.env_list[name] = lst

    # Ambiguity purge: a name bound to objects of two different
    # modules in one file (typically the same local name reused in two
    # functions for two different clients) cannot be resolved honestly
    # with a flat table — drop it, so its sends are not classified on
    # a guess. Single-module names (however often rebound) are kept.
    for name, modules in sym.obj_candidates.items():
        if len(modules) > 1:
            sym.var_obj.pop(name, None)
    for dotted, modules in sym.attr_candidates.items():
        if len(modules) > 1:
            sym.attr_obj.pop(dotted, None)


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
# Constructors whose result IS an HTTP client: a method call chained
# straight onto one (`requests.Session().post(...)`,
# `httpx.Client().post(...)`) or made through a variable bound to one
# is a call on that library, not on an unknown object.
_SESSION_CTORS = {
    "requests.Session", "requests.session",
    "httpx.Client", "httpx.AsyncClient",
    "aiohttp.ClientSession",
}


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

        # Chained session/client calls: `requests.Session().post(url)`
        # has no name to resolve — the receiver is the constructor call
        # itself. Resolve it onto the library so the HTTP branch below
        # treats it exactly like a variable-bound session (SESSION_SEND).
        if not dotted and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Call):
            ctor = _resolve(node.func.value.func, sym)
            if ctor in _SESSION_CTORS:
                dotted = ctor.rsplit(".", 1)[0] + "." + node.func.attr

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

        # HTTP client calls (alias-resolved). aiohttp is session-only,
        # so it reaches this branch through a bound/chained client.
        if module in ("requests", "httpx", "aiohttp"):
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

    # Predictable-temp-path execution (ENV_INJECTION, Python side):
    # an exec/chmod call whose folded arguments name a fixed /tmp
    # path — directly, or through a variable assigned that literal —
    # runs or arms a file anyone could have predicted and planted.
    # The tie is to the PATH: an unrelated subprocess call elsewhere
    # in the file does not complete the shape.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _resolve(node.func, sym)
        if dotted.startswith("subprocess.") or dotted in (
                "os.system", "os.popen", "os.chmod", "os.chown") \
                or dotted.startswith(("os.exec", "os.spawn")):
            for s in _call_strings(node, sym):
                m = _TMP_PATH_RE.search(s)
                if m and "XXX" not in m.group(0):
                    add("ENV_INJECTION", rel, node.lineno)
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


_ENV_INJECT_VARS = ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP")
# Install/startup contexts (lifecycle commands, manifest command/args,
# setup.py, .pth files) also treat PYTHONPATH as an injection
# variable: it steers every later interpreter's module search. It is
# deliberately NOT in _ENV_INJECT_VARS proper — an MCP manifest env
# entry pointing PYTHONPATH at the server's own code is a common,
# legitimate configuration, while SETTING it from an install script
# or a startup file is the injection shape.
_ENV_INJECT_VARS_INSTALL = _ENV_INJECT_VARS + ("PYTHONPATH",)
_ENV_INJECT_SET_RE = re.compile(
    r"\b(LD_PRELOAD|DYLD_INSERT_LIBRARIES|PYTHONSTARTUP|PYTHONPATH)\s*=")


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
                if _ENV_INJECT_SET_RE.search(command):
                    add("ENV_INJECTION_INSTALL", rel, _find_line(lines, command))
            args = cfg.get("args")
            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str) and _ENV_INJECT_SET_RE.search(arg):
                        add("ENV_INJECTION_INSTALL", rel, _find_line(lines, arg))
            env = cfg.get("env")
            if isinstance(env, dict):
                for key in env:
                    if str(key) in _ENV_INJECT_VARS:
                        # A manifest that starts its server with a loader
                        # preload in the environment injects code into
                        # every run — install-context, so it blocks.
                        add("ENV_INJECTION_INSTALL", rel, _find_line(lines, str(key)))
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
            if _ENV_INJECT_SET_RE.search(command):
                add("ENV_INJECTION_INSTALL", rel, line, command)
    elif path.name == "setup.py":
        # setup.py is EXECUTED by pip at install/build time. A setup.py
        # that only declares metadata is fine; one reaching for
        # subprocess/network/sockets is install-time code execution.
        # Comments are stripped first: prose about subprocess is not
        # subprocess. The same behaviour check is applied ONE LEVEL deep
        # to local modules setup.py imports, since the payload commonly
        # sits in the imported file.
        code = _strip_py_comments(text)
        # An install-time file that arms a loader preload for later
        # processes is the install-context injection shape: it blocks.
        for lineno, line in enumerate(code.splitlines(), start=1):
            if "environ" in line and any(
                    var in line for var in _ENV_INJECT_VARS_INSTALL):
                evidence = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
                add("ENV_INJECTION_INSTALL", rel, lineno, evidence)
                break
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
# Concealment mechanics: hidden text, non-English instruction phrases,
# Markdown hiding places, predictable-temp-file injection shapes
# --------------------------------------------------------------------------
#
# These matchers judge MECHANICS, never meaning: characters that render
# invisibly, elements styled to be unseen, known attack PHRASES in a
# fixed list of languages. Whether prose is *deceptive* remains a
# semantic judgement no rule here attempts (see AUDIT_COVERAGE.md).

_INSTRUCTION_KEYWORDS = (
    "ignore", "instruction", "secret", "password", "credential",
    "exfiltrat", "curl", "wget", "download", "execute", "system prompt",
    "do not tell", "don't tell", "never tell", "hide this",
    "api key", "api_key", "access token", "private key", "send the",
    "send all", "upload the", ".ssh", "id_rsa",
)


def _has_instruction_keyword(text: str) -> bool:
    low = text.lower()
    return any(kw in low for kw in _INSTRUCTION_KEYWORDS)


# Instruction-GRADE keywords, for surfaces where a merely topical word
# must not be enough (HTML comments, Markdown-hidden content): either
# a strong instruction/credential keyword on its own, or a send verb
# TOGETHER WITH a credential target — the verb+target co-occurrence
# shape. A bare "send the …" (a TODO about an invoice template) or a
# bare "download" (an FAQ answer) does not meet this bar.
_STRONG_KEYWORDS = (
    "ignore", "instruction", "secret", "password", "credential",
    "exfiltrat", "system prompt", "api key", "api_key",
    "access token", "private key", ".ssh", "id_rsa",
    "do not tell", "don't tell", "never tell", "hide this",
    "curl", "wget",
)
_SEND_VERB_WORDS = (
    "send", "upload", "mail", "forward", "deliver", "post",
)
_TARGET_WORDS = (
    "password", "credential", "secret", "token", "api key", "ssh key",
    ".ssh", "id_rsa", "private key", ".env", ".aws",
    "file contents", "contents of",
)


def _has_instruction_grade_keyword(text: str) -> bool:
    low = text.lower()
    if any(kw in low for kw in _STRONG_KEYWORDS):
        return True
    return any(v in low for v in _SEND_VERB_WORDS) \
        and any(t in low for t in _TARGET_WORDS)


# --- hidden text --------------------------------------------------------

_ZW_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_TAG_RUN_RE = re.compile(r"[\U000E0000-\U000E007F]{2,}")
_BIDI_CHARS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
_HTML_COMMENT_RE = re.compile(r"<!--")
_TEST_BANNER_RE = re.compile(
    r"(do not run|scanning test|test sample|sample for test|"
    r"for testing purposes|not a real skill|fictional sample)",
    re.IGNORECASE)


def _decode_tag_run(run: str) -> str:
    """Unicode Tags characters encode ASCII by adding 0xE0000; decode
    the printable slice of a run back to the text it hides."""
    out = []
    for ch in run:
        value = ord(ch) - 0xE0000
        if 0x20 <= value < 0x7F:
            out.append(chr(value))
    return "".join(out)


def _zw_line_suspicious(line: str, is_first_line: bool) -> bool:
    """Suspicious-context test for zero-width characters, so ordinary
    multilingual text does NOT fire: a single zero-width joiner inside
    Persian / Arabic / Indic text, or inside an emoji sequence, is
    legitimate typography. Suspicious means: a run of two or more, any
    zero-width char in an otherwise-ASCII line, or one sitting in a
    line that carries instruction keywords."""
    idxs = [i for i, ch in enumerate(line) if ch in _ZW_CHARS]
    if is_first_line:
        # A byte-order mark at the very start of a file is an encoding
        # marker, not concealment (and the UTF-8/16 BOMs are already
        # stripped by _decode — this covers a stray one in content).
        idxs = [i for i in idxs if not (i == 0 and line[0] == "\ufeff")]
    if not idxs:
        return False
    runs = 1
    for prev, cur in zip(idxs, idxs[1:]):
        runs = runs + 1 if cur == prev + 1 else 1
        if runs >= 2:
            return True
    stripped = "".join(ch for ch in line if ch not in _ZW_CHARS)
    if all(ord(ch) < 128 for ch in stripped):
        return True  # invisible characters inside plain ASCII text
    return _has_instruction_keyword(line)


def _bidi_line_suspicious(line: str, doc: bool) -> bool:
    if not any(ch in line for ch in _BIDI_CHARS):
        return False
    if not doc:
        return True  # bidi controls in code: the Trojan Source shape
    # In documentation, bidi controls can be legitimate in RTL prose.
    # Fire only when the line is mostly Latin/ASCII content or carries
    # instruction keywords — not for ordinary Arabic/Hebrew text.
    letters = [ch for ch in line if ch.isalpha()]
    if not letters:
        return True
    ascii_share = sum(1 for ch in letters if ord(ch) < 128) / len(letters)
    return ascii_share > 0.5 or _has_instruction_keyword(line)


def _html_comments(text: str) -> list[tuple[int, str]]:
    """(start offset, body) for every HTML comment. An UNCLOSED
    comment's body runs to the end of the file — truncating it would
    let a payload hide past an arbitrary window."""
    out = []
    for m in _HTML_COMMENT_RE.finditer(text):
        end = text.find("-->", m.end())
        body = text[m.end():] if end == -1 else text[m.end():end]
        out.append((m.start(), body))
    return out


def _is_pure_banner(body: str) -> bool:
    """A comment is skippable ONLY when it is banner/safety text
    through and through: it carries a test-banner phrase AND no
    instruction-grade keyword content. A banner phrase riding on the
    same comment as a payload does NOT exempt the payload — the
    comment is then checked normally (and fires at CAUTION like any
    other keyword-carrying comment)."""
    return bool(_TEST_BANNER_RE.search(body)) \
        and not _has_instruction_grade_keyword(body)


_STEP_LABEL_RE = re.compile(
    r"^\s*step\s+[\w]+\s*[:.)\u2014-]\s*", re.IGNORECASE)


def _squeezed_comment_text(bodies: list[str]) -> str:
    """Reconstruct text split ACROSS comments: drop enumeration
    labels ("step two:") at body starts, join the bodies, and remove
    all whitespace — the comment-level analogue of the JS string
    squeeze, so a token split as "~/.s" | "h/id_r" | "sa" is checked
    as the single string it reassembles into."""
    parts = [_STEP_LABEL_RE.sub("", b) for b in bodies]
    return re.sub(r"\s+", "", " ".join(parts))


def _hidden_text_findings(rel: str, text: str, lines: list[str],
                          doc: bool, add) -> None:
    # BLOCK pass: a Tags-block payload whose decoded text contains
    # instruction keywords is a smuggled instruction, full stop. The
    # runs are checked individually AND as one file-level
    # concatenation — splitting a keyword across two runs (or across
    # a line break) must not demote it.
    runs = [(m.start(), m.group(0)) for m in _TAG_RUN_RE.finditer(text)]
    if runs:
        block_at = None
        for pos, run in runs:
            if _has_instruction_keyword(_decode_tag_run(run)):
                block_at = pos
                break
        if block_at is None:
            joined = _decode_tag_run("".join(run for _, run in runs))
            if _has_instruction_keyword(joined):
                block_at = runs[0][0]
        if block_at is not None:
            line_no = text[:block_at].count("\n") + 1
            add("HIDDEN_TEXT", rel, line_no,
                lines[line_no - 1] if 0 < line_no <= len(lines) else "")
            return
    # CAUTION pass: any other concealment indicator in this file.
    caution_line = None
    if runs:
        caution_line = text[:runs[0][0]].count("\n") + 1
    if caution_line is None:
        for lineno, line in enumerate(lines, start=1):
            if _zw_line_suspicious(line, lineno == 1) \
                    or _bidi_line_suspicious(line, doc):
                caution_line = lineno
                break
    if caution_line is None:
        # Tags characters interleaved with zero-width characters (one
        # character per "run", each below the run-length threshold)
        # are still Tags characters: two or more on one line, however
        # arranged, are a presence hit.
        for lineno, line in enumerate(lines, start=1):
            if sum(1 for ch in line
                   if "\U000E0000" <= ch <= "\U000E007F") >= 2:
                caution_line = lineno
                break
    if caution_line is None:
        # HTML comments whose body carries instruction-grade content.
        comments = _html_comments(text)
        for pos, body in comments:
            if _is_pure_banner(body):
                continue
            if _has_instruction_grade_keyword(body):
                caution_line = text[:pos].count("\n") + 1
                break
        if caution_line is None and len(comments) > 1:
            # A payload split ACROSS comments: check the bodies joined
            # (word-boundary splits) and squeezed (token splits).
            bodies = [body for _, body in comments]
            if _has_instruction_grade_keyword(" ".join(bodies)) \
                    or _has_instruction_grade_keyword(
                        _squeezed_comment_text(bodies)):
                caution_line = text[:comments[0][0]].count("\n") + 1
    if caution_line is not None:
        evidence = lines[caution_line - 1] if 0 < caution_line <= len(lines) else ""
        add("HIDDEN_TEXT", rel, caution_line, evidence,
            severity_cap="caution")


# --- non-English instruction phrases ------------------------------------
#
# A fixed phrase list per language, in three shapes: an override of
# earlier instructions (fires alone), a send/steal verb together with a
# credential/file target on the same line, and a keep-it-from-the-user
# phrase (fires alone). Written for this scanner; deliberately narrow —
# ordinary prose in these languages does not contain these imperatives.

# Phrase sets live in per-language JSON data files inside the package
# (skillscan/phrases/<code>.json), each holding the same three shapes:
# "override" (ignore-override imperatives), "conceal" (do-not-tell-the
# -user imperatives) and "send" + "target" (send-verbs that fire only
# together with a credential target). Adding a language = adding one
# file; no code change is needed. A file that fails to parse is
# skipped rather than breaking the scan (the same degrade-don't-crash
# rule as every other matcher).
def _load_phrase_sets() -> list[dict]:
    import json as _json
    sets: list[dict] = []
    phrases_dir = Path(__file__).parent / "phrases"
    try:
        files = sorted(phrases_dir.glob("*.json"))
    except OSError:
        return sets
    for f in files:
        try:
            data = _json.loads(f.read_text(encoding="utf-8"))
            lang = {
                "code": str(data["code"]),
                "cjk": bool(data.get("cjk", False)),
                "override": tuple(data.get("override", ())),
                "send": tuple(data.get("send", ())),
                "target": tuple(data.get("target", ())),
                "conceal": tuple(data.get("conceal", ())),
            }
        except Exception:
            continue
        # Send-verbs for space-separated scripts match as whole
        # TOKENS, so a noun that merely contains a verb ("Sendung" —
        # a shipment — contains "sende") never fires. Scripts whose
        # verbs do not end at a clean token boundary keep substring
        # matching and only ever fire together with a credential
        # target (the full shape): Chinese and Japanese (no spaces),
        # and Korean (verbs agglutinate suffixes).
        lang["substring_verbs"] = bool(
            lang["cjk"] or data.get("substring_verbs", False))
        lang["verb_set"] = frozenset(v.lower() for v in lang["send"])
        sets.append(lang)
    return sets


_NON_ENGLISH_RULES: list[dict] = _load_phrase_sets()
_NON_ENGLISH_NEGATIONS = (
    "nunca", "jamais", "niemals", "nie ", "nigdy", "asla", "绝不",
    "決して", "никогда", "कभी नहीं", "não", "nao ", "never", "refuse",
    "أبداً", "절대", "jangan pernah", "ніколи",
)


_TOKEN_EDGE_CHARS = " \t.,;:!?()[]{}<>\"'«»“”„‚‘’—–-।॥·。、،؛؟…*_`#"


def _verb_hit(low: str, lang: dict) -> bool:
    """Send-verb match for one language on an already-lowercased line:
    whole-token equality (with 2- and 3-token windows for multiword
    verbs) for space-separated scripts, substring for the scripts
    flagged substring_verbs."""
    if lang.get("substring_verbs"):
        return any(v in low for v in lang["send"])
    verbs = lang.get("verb_set") or frozenset()
    if not verbs:
        return False
    tokens = [t.strip(_TOKEN_EDGE_CHARS) for t in low.split()]
    tokens = [t for t in tokens if t]
    for n in (1, 2, 3):
        for i in range(len(tokens) - n + 1):
            if " ".join(tokens[i:i + n]) in verbs:
                return True
    return False


def _non_english_findings(rel: str, lines: list[str], add) -> None:
    for lineno, line in enumerate(lines, start=1):
        low = line.lower()
        if any(neg in low for neg in _NON_ENGLISH_NEGATIONS):
            continue  # safety prose in any language is not an attack
        for lang in _NON_ENGLISH_RULES:
            if any(p in low for p in lang["override"]) \
                    or any(p in low for p in lang["conceal"]):
                add("NON_ENGLISH_INSTRUCTION", rel, lineno, line)
                return
            if _verb_hit(low, lang) \
                    and any(t in low for t in lang["target"]):
                add("NON_ENGLISH_INSTRUCTION", rel, lineno, line)
                return


# --- language-independent structure (ANY_LANGUAGE_STRUCTURE) ------------
#
# The exfiltration shape needs no phrase list: a PRIVATE credential
# store named in the same breath as an outbound destination is the
# shape in every language. Anchor (a) is deliberately a private-store
# location (~/.ssh, ~/.aws, a .env file, an SSH key file, a browser
# credential store) — NOT the bare word "token": a guide that tells
# users to send their own token to the service's own API URL is normal
# documentation. Anchor (b) is a destination or fetch command (URL,
# IP, email address, curl/wget, webhook). Negation/safety prose is
# skipped with the same guard as the line pass.
_PRIVATE_STORE_RE = re.compile(
    r"~/\.(ssh|aws|gnupg|config/gh)\b"
    r"|\.ssh[/\\]"
    r"|id_(rsa|dsa|ecdsa|ed25519)\b"
    r"|\.env\b[\w./\\-]*"
    r"|~/\.aws\b|\.aws[/\\]credentials\b"
    r"|login\s+data\b|logins\.json|key4\.db|cookies\.sqlite"
    r"|browser\s+(password|credential|cookie)s?\s+(store|vault|database|file)",
    re.IGNORECASE)
_OUTBOUND_RE = re.compile(
    r"https?://|ftp://|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|\b[\w.+-]+@[\w-]+\.[\w.]+\b"
    r"|\bcurl\b|\bwget\b|webhook", re.IGNORECASE)


def _any_language_structure_findings(rel: str, lines: list[str],
                                     add) -> None:
    for lineno, line in enumerate(lines, start=1):
        if NEGATION_RE.search(line):
            continue  # safety prose warning against the shape
        if _PRIVATE_STORE_RE.search(line) and _OUTBOUND_RE.search(line):
            add("ANY_LANGUAGE_STRUCTURE", rel, lineno, line,
                severity_cap="caution")
            return


# --- Markdown concealment ------------------------------------------------

_STYLE_ATTR_RE = re.compile(r"style\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
_HIDDEN_STYLE_RE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"opacity\s*:\s*0(\.0+)?\b)", re.IGNORECASE)
_TAG_STRIP_RE = re.compile(r"<[^>]*>")
_DETAILS_RE = re.compile(r"<details[^>]*>(.*?)</details>",
                         re.IGNORECASE | re.DOTALL)
_HIDDEN_TAG_RE = re.compile(r"<\w+[^>]*\bhidden\b[^>]*>", re.IGNORECASE)


def _style_is_hiding(style: str) -> bool:
    if _HIDDEN_STYLE_RE.search(style):
        return True
    low = style.lower()
    # Off-screen positioning: text kept in the document but pushed
    # far outside the rendered area.
    compact = re.sub(r"\s+", "", low)
    if "position:absolute" in compact or "position:fixed" in compact:
        for prop in ("left:", "top:"):
            m = re.search(re.escape(prop) + r"(-?\d+(?:\.\d+)?)px",
                          compact)
            if m and float(m.group(1)) <= -100:
                return True
    m = re.search(r"text-indent\s*:\s*(-?\d+(?:\.\d+)?)px", low)
    if m and float(m.group(1)) <= -999:
        return True
    white = ("white", "#fff", "#ffffff", "rgb(255,255,255)",
             "rgb(255, 255, 255)")
    has_fg = "color:" in low.replace("background-color:", "") \
        and any(w in low for w in white)
    has_bg = ("background" in low) and any(w in low for w in white)
    return bool(has_fg and has_bg)


def _markdown_concealment_findings(rel: str, text: str, lines: list[str],
                                   add) -> None:
    def content_after(pos: int, tag: str = "") -> str:
        # Read to the element's MATCHING close tag (counting nested
        # elements of the same tag), with a 4000-char window as the
        # fallback — stopping at the first nested "</" would let a
        # payload hide behind one nested element.
        if tag:
            close_re = re.compile(
                r"</?\s*" + re.escape(tag) + r"(?:\s[^<>]*)?>",
                re.IGNORECASE)
            depth = 1
            limit = min(len(text), pos + 4000)
            for cm in close_re.finditer(text, pos):
                if cm.start() > limit:
                    break
                if cm.group(0).startswith("</"):
                    depth -= 1
                    if depth == 0:
                        return _TAG_STRIP_RE.sub(
                            " ", text[pos:cm.start()])
                elif not cm.group(0).endswith("/>"):
                    depth += 1
            return _TAG_STRIP_RE.sub(" ", text[pos:limit])
        return _TAG_STRIP_RE.sub(" ", text[pos:pos + 4000])

    # Instruction-GRADE keywords only, everywhere below: bare words
    # like "download" are ordinary documentation, even when hidden.
    for m in _STYLE_ATTR_RE.finditer(text):
        # Locate the end of the opening tag carrying this style.
        tag_end = text.find(">", m.end())
        if tag_end == -1 or not _style_is_hiding(m.group(1)):
            continue
        tag_m = re.search(r"<\s*([a-zA-Z][\w-]*)",
                          text[max(0, m.start() - 200):m.start()])
        if _has_instruction_grade_keyword(
                content_after(tag_end + 1, tag_m.group(1) if tag_m else "")):
            line_no = text[:m.start()].count("\n") + 1
            add("MARKDOWN_CONCEALMENT", rel, line_no,
                lines[line_no - 1] if 0 < line_no <= len(lines) else "")
            return
    for m in _HIDDEN_TAG_RE.finditer(text):
        tag_m = re.match(r"<\s*([a-zA-Z][\w-]*)", m.group(0))
        if _has_instruction_grade_keyword(
                content_after(m.end(), tag_m.group(1) if tag_m else "")):
            line_no = text[:m.start()].count("\n") + 1
            add("MARKDOWN_CONCEALMENT", rel, line_no,
                lines[line_no - 1] if 0 < line_no <= len(lines) else "")
            return
    for m in _DETAILS_RE.finditer(text):
        # A plain <details> is a disclosure widget, not concealment —
        # it only counts when its opening tag ALSO carries a hiding
        # style or the hidden attribute.
        opening = m.group(0)[:m.group(0).find(">") + 1]
        style_m = _STYLE_ATTR_RE.search(opening)
        if not (bool(style_m and _style_is_hiding(style_m.group(1)))
                or _HIDDEN_TAG_RE.search(opening)):
            continue
        inner = _TAG_STRIP_RE.sub(" ", m.group(1))
        if _has_instruction_grade_keyword(inner):
            line_no = text[:m.start()].count("\n") + 1
            add("MARKDOWN_CONCEALMENT", rel, line_no,
                lines[line_no - 1] if 0 < line_no <= len(lines) else "")
            return


# --- predictable temp file + execute --------------------------------------

_TMP_PATH_RE = re.compile(r"/tmp/[A-Za-z0-9_.\-]{1,80}")
_EXEC_CONTEXT_RE = re.compile(
    r"(chmod|os\.chmod|subprocess|Popen|os\.system|os\.exec|exec[lv]\b|"
    r"/bin/(ba)?sh\b)")


def _env_injection_findings(rel: str, text: str, lines: list[str],
                            add) -> None:
    """A fixed, guessable path under /tmp that the same file also makes
    executable or runs is the insecure-temp-file shape: anyone (or any
    other process) can predict the name, and whatever lands there gets
    executed or loaded. The execution context must be tied to THE SAME
    path — the literal itself on an exec/chmod line, a variable bound
    to that literal used there (one-hop name tracking: shell files
    arrive here already variable-expanded, other files are matched by
    name), or the path standing in command position. An unrelated
    subprocess call elsewhere in the file does NOT complete the shape,
    and neither does a mere second mention. Python files get the same
    check with exact argument folding in the AST pass. Lines that warn
    against the shape (negation prose) are ignored, as in the line
    pass."""
    hits: dict[str, list[int]] = {}
    names: dict[str, set[str]] = {}
    for lineno, line in enumerate(lines, start=1):
        if NEGATION_RE.search(line):
            continue
        for m in _TMP_PATH_RE.finditer(line):
            hits.setdefault(m.group(0), []).append(lineno)
        am = re.match(
            r"\s*(?:export\s+)?([A-Za-z_][\w]*)\s*[:?+]?=\s*[\"']?"
            r"(/tmp/[A-Za-z0-9_.\-]+)", line)
        if am:
            names.setdefault(am.group(2), set()).add(am.group(1))
    if not hits:
        return

    def line_tied(line: str, path: str) -> bool:
        if path in line and _EXEC_CONTEXT_RE.search(line):
            return True
        stripped = line.strip().strip("\"'")
        if stripped == path or stripped.startswith((path + " ",
                                                    path + ";")):
            return True  # the path itself stands in command position
        if not _EXEC_CONTEXT_RE.search(line):
            return False
        return any(
            re.search(r"\$\{?" + re.escape(n) + r"\b", line)
            or re.search(r"\b" + re.escape(n) + r"\b", line)
            for n in names.get(path, ()))

    for path, hit_lines in hits.items():
        if "XXX" in path:
            continue  # an mktemp-style template is not a fixed path
        if any(line_tied(line, path) for line in lines):
            first = hit_lines[0]
            add("ENV_INJECTION", rel, first, lines[first - 1])
            return


# --- download-through-substitution (SUBSTITUTION_EXEC) --------------------

_SUBST_INNER_RE = re.compile(
    r"(?:\$\(\s*(?:shell\s+)?|`)([^)`]*)", re.IGNORECASE)
_SUBST_FETCH_RE = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
_PROCESS_SUBST_RE = re.compile(r"<\(\s*(?:curl|wget)\b", re.IGNORECASE)
_EXECUTING_CMD_RE = re.compile(
    r"\b(eval|exec|source|xargs)\b|\b(?:ba|da|z|k)?sh\s+-c\b"
    r"|\bbash\s+-c\b|\bsh\s+-\w*c\b", re.IGNORECASE)
_BENIGN_CONSUMER_RE = re.compile(
    r"^\s*(?:echo|printf|cat|test|\[|if\b|while\b|until\b|case\b|"
    r"return\b|export\b|local\b|declare\b|readonly\b)", re.IGNORECASE)
_ASSIGN_PREFIX_RE = re.compile(
    r"^\s*(?:export\s+|local\s+|declare\s+|readonly\s+)?"
    r"[A-Za-z_][\w]*\s*[:?+]?=")


def _squeeze_shell_line(line: str) -> str:
    """Normalise shell quoting tricks before matching: drop empty
    quote pairs (cu''rl -> curl) and remove quote characters between
    adjacent quoted fragments ('cu'"rl" -> curl)."""
    prev = None
    out = line
    while prev != out:
        prev = out
        out = out.replace("''", "").replace('""', "")
        out = re.sub(r"(['\"])\1+", r"\1", out)
        out = re.sub(r"(['\"])(?=[A-Za-z])", "", out)
        out = re.sub(r"(?<=[A-Za-z])(['\"])", "", out)
    return out


def _substitution_exec_findings(rel: str, lines: list[str], add) -> None:
    """Classify every download-through-substitution site in the file.
    A substitution in an EXECUTING context (command position, eval /
    sh -c / source, piped to a shell, process substitution) is BLOCK:
    the fetched content runs. A substitution that only CAPTURES the
    download (VAR=$(curl …) whose value is never executed by this
    file, a Makefile $(shell …) assignment) is the same shape at
    CAUTION: worth a human look, not proof of execution. Shell files
    arrive variable-expanded, so a captured variable that IS later
    executed shows up here as an executing line in its own right."""
    sites: list[tuple[int, bool, str]] = []  # (lineno, executing, line)
    for lineno, raw in enumerate(lines, start=1):
        line = _squeeze_shell_line(raw)
        if _PROCESS_SUBST_RE.search(line):
            sites.append((lineno, True, raw))
            continue
        for m in _SUBST_INNER_RE.finditer(line):
            inner = m.group(1)
            if not _SUBST_FETCH_RE.search(inner):
                continue
            prefix = line[:m.start()]
            if _EXECUTING_CMD_RE.search(line) \
                    or _EXECUTING_CMD_RE.search(inner):
                executing = True
            elif _ASSIGN_PREFIX_RE.match(line):
                executing = False  # pure capture into a variable
            elif _BENIGN_CONSUMER_RE.match(line):
                executing = False  # echo/printf/test consumption
            elif prefix.strip() == "" \
                    or prefix.rstrip().endswith((";", "&", "|", "(")):
                executing = True   # substitution in command position
            else:
                executing = False  # argument to some other command
            sites.append((lineno, executing, raw))
    # A captured variable that a LATER line executes promotes its
    # capture site to executing. (The shell expansion pass inlines
    # simple captures before this matcher runs, but not every quoting
    # shape, so the names are tracked directly as well.)
    captured: dict[str, int] = {}
    for lineno, raw in enumerate(lines, start=1):
        line = _squeeze_shell_line(raw)
        if _ASSIGN_PREFIX_RE.match(line) \
                and ("$(" in line or "`" in line) \
                and _SUBST_FETCH_RE.search(line):
            name_m = re.search(r"([A-Za-z_][\w]*)\s*[:?+]?=", line)
            if name_m:
                captured[name_m.group(1)] = lineno
    if captured and sites:
        executed: set[int] = set()
        for lineno, raw in enumerate(lines, start=1):
            line = _squeeze_shell_line(raw)
            for var, cap_line in captured.items():
                if lineno <= cap_line:
                    continue
                if not re.search(r"\$\{?" + re.escape(var) + r"\b",
                                 line):
                    continue
                stripped = line.strip().strip("\"'")
                if _EXECUTING_CMD_RE.search(line) \
                        or stripped in ("$" + var, "${" + var + "}") \
                        or re.search(r"\|\s*(?:ba|da|z|k)?sh\b", line):
                    executed.add(cap_line)
        if executed:
            sites = [(ln, ex or ln in executed, raw)
                     for ln, ex, raw in sites]
    if not sites:
        return
    if any(executing for _, executing, _ in sites):
        lineno, _, raw = next(s for s in sites if s[1])
        add("SUBSTITUTION_EXEC", rel, lineno, raw)
    else:
        lineno, _, raw = sites[0]
        add("SUBSTITUTION_EXEC", rel, lineno, raw,
            severity_cap="caution")


# --- .pth startup files -----------------------------------------------------

_PTH_IMPORT_RE = re.compile(r"^\s*import\s+\S")
_PTH_ENV_RE = re.compile(
    r"(os\.environ|sys\.path|PYTHONPATH|LD_PRELOAD|PYTHONSTARTUP)")


def _pth_findings(rel: str, lines: list[str], add) -> None:
    """A .pth file in a site-packages directory is executed line by
    line at EVERY interpreter startup: lines starting with `import`
    run as code. That makes a .pth an install/startup surface of its
    own — an import line, or any environment/path manipulation, is
    ENV_INJECTION_INSTALL-tier. Plain path entries and comments (the
    only lines a benign .pth contains) pass."""
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _PTH_IMPORT_RE.match(line) or _PTH_ENV_RE.search(line):
            add("ENV_INJECTION_INSTALL", rel, lineno, line)
            return


# --------------------------------------------------------------------------
# Main scan
# --------------------------------------------------------------------------

# Extensions that count as inspectable source for the compiled-binary
# coverage check: a folder shipping source alongside a binary helper is
# a normal build layout; a folder whose ONLY code is compiled is a
# folder whose behaviour cannot be inspected at all.
_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".c", ".h",
    ".cc", ".cpp", ".hpp", ".rs", ".go", ".java", ".rb", ".pl", ".php",
    ".sh", ".bash", ".ps1", ".lua",
}
_NATIVE_BINARY_EXTENSIONS = {".so", ".dll", ".exe", ".dylib"}


def _folder_inventory(root: Path) -> tuple[set[tuple[str, str]], bool]:
    """Cheap name-only pre-pass: which (directory, stem) pairs have a
    .py source, and does the folder contain any source file at all?
    Used to judge compiled files (bytecode / native binaries) whose
    behaviour a text scan cannot inspect."""
    py_sources: set[tuple[str, str]] = set()
    has_source = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS]
        rel_dir = str(Path(dirpath).relative_to(root))
        for name in filenames:
            suffix = Path(name).suffix.lower()
            if suffix == ".py":
                py_sources.add((rel_dir, Path(name).stem))
            if suffix in _SOURCE_EXTENSIONS:
                has_source = True
    return py_sources, has_source


def scan_folder(root: Path) -> ScanResult:
    root = root.resolve()
    result = ScanResult(target=str(root))
    py_sources, folder_has_source = _folder_inventory(root)
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
            reason = "binary-looking content"
            if suffix in (".pyc", ".pyo"):
                # Compiled Python bytecode with no matching .py source
                # is code the scan cannot inspect at all: calling it a
                # routine binary skip would let a bytecode-only skill
                # read as clean. With its source beside it, it is an
                # ordinary build artefact and stays non-suspicious.
                # Stems compare in full on both sides, with the
                # interpreter tag stripped (x.cpython-312.pyc pairs
                # with x.py; a.b.pyc pairs with a.b.py).
                base = re.sub(r"\.cpython-\d+$", "",
                              path.name[: -len(suffix)])
                if (str(path.parent.relative_to(root)), base) \
                        not in py_sources:
                    suspicious = True
                    reason = ("compiled Python bytecode with no matching "
                              ".py source — cannot be inspected")
            elif suffix in _NATIVE_BINARY_EXTENSIONS \
                    and not folder_has_source:
                suspicious = True
                reason = ("compiled binary with no source code in the "
                          "folder — cannot be inspected")
            result.skipped.append(Skipped(rel, reason, suspicious))
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
            # Parsed-value pass: escapes in the raw text (\uXXXX and
            # friends) decode away in the parsed values, so run the
            # hidden-text, non-English and structure matchers over the
            # string VALUES themselves — an escaped payload is caught
            # after decoding. (Line numbers refer to the value list.)
            try:
                parsed = json.loads(text)

                def _string_values(node):
                    if isinstance(node, str):
                        yield node
                    elif isinstance(node, dict):
                        for v in node.values():
                            yield from _string_values(v)
                    elif isinstance(node, list):
                        for v in node:
                            yield from _string_values(v)

                value_lines = list(_string_values(parsed))
                if value_lines:
                    _hidden_text_findings(
                        rel, "\n".join(value_lines), value_lines, True,
                        add)
                    _non_english_findings(rel, value_lines, add)
                    _any_language_structure_findings(
                        rel, value_lines, add)
            except Exception:
                pass

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
        # raw-socket reverse shells, package install-time behaviour,
        # concealment mechanics, non-English instruction phrases,
        # predictable-temp-file shapes. Hostile input must never crash
        # the scan — failures here degrade to a coverage note, like
        # manifest analysis above.
        try:
            _secret_findings(rel, path, lines, doc, add)
            _reverse_shell_findings(rel, text, lines, add)
            _package_findings(rel, path, text, lines, add, root,
                              note=result.skipped.append)
            _hidden_text_findings(rel, text, lines, doc, add)
            _env_injection_findings(rel, text, scan_lines, add)
            _substitution_exec_findings(rel, scan_lines, add)
            if suffix == ".pth":
                _pth_findings(rel, lines, add)
            if doc:
                _markdown_concealment_findings(rel, text, lines, add)
                _any_language_structure_findings(rel, lines, add)
            if doc or suffix == ".json":
                _non_english_findings(rel, lines, add)
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
