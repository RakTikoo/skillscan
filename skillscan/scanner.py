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


# --- v0.5 taint-lite (design §2) -------------------------------------------
# Minimal intra-file value-flow for Python: which *kinds* of source a
# value came from, tracked through plain assignments, containers,
# f-strings, transparent wrappers and file-local function returns.
# Source kinds: "cred" (credential material — the only kind that can
# BLOCK), "envsecret" (secret-named environment variable), "env",
# "file", "input". There is deliberately NO sanitiser modelling:
# base64-encoding a credential does not clean it.

_CRED_FILENAME_TOKENS = {
    "token", "credentials", "credential", "secret", "secrets",
    "api_key", "apikey", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}
_SECRET_NAME_RE = re.compile(
    r"(key|token|secret|password|passwd|credential|auth)", re.IGNORECASE)
_TAINT_WRAPPERS = {
    "str", "bytes", "json.dumps", "base64.b64encode",
    "base64.b64decode", "binascii.hexlify", "binascii.unhexlify",
}


def _classify_path_value(value: str) -> str | None:
    """'cred' when a path string names credential material, else None.
    Same placeholder discipline as _check_credential_value: examples
    and documentation placeholders never classify."""
    if _PLACEHOLDER_ENV_RE.search(value):
        return None
    low = value.lower()
    base = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
    if base.endswith(".pub"):
        # A public key is meant to be shared; it is not credential
        # material even inside ~/.ssh (FP hunt: pubkey registrar).
        return None
    if ".ssh" in low or ".aws" in low or ".azure" in low \
            or ".gcloud" in low:
        return "cred"
    if any(frag in value for frag in _BROWSER_STORE_FRAGMENTS):
        return "cred"
    if value == ".env" or value.endswith("/.env") or "/.env" in value:
        return "cred"
    if base in _CRED_FILENAME_TOKENS or base.endswith(".key"):
        return "cred"
    if base.endswith(".pem"):
        # A .pem is as often a public CERTIFICATE as a private key;
        # the extension alone does not classify it (FP hunt: cert
        # uploader). A key-ish stem (client-key.pem, privkey.pem,
        # api_token.pem) still does.
        stem = base[:-4]
        parts = set(re.split(r"[-_.]+", stem))
        if stem in _CRED_FILENAME_TOKENS or parts & {
                "key", "privkey", "private", "token", "secret",
                "credentials", "credential"}:
            return "cred"
    return None


def _path_candidates(node: ast.AST, sym: _Symbols) -> list[str]:
    """String pieces an expression might denote: folded value, list
    elements (index joins Path / parts[i] shapes included), plain
    constants and environment strings."""
    out: list[str] = []
    folded = _fold_str(node, sym)
    if folded:
        out.append(folded)
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.append(sub.value)
        elif isinstance(sub, ast.Name) and sub.id in sym.env_str:
            out.append(sym.env_str[sub.id])
        elif isinstance(sub, ast.Subscript) \
                and isinstance(sub.value, ast.Name):
            lst = sym.env_list.get(sub.value.id)
            idx = sub.slice.value if isinstance(sub.slice, ast.Constant) \
                else None
            if lst and isinstance(idx, int) and 0 <= idx < len(lst):
                out.append(str(lst[idx]))
    return out


def _classify_read_expr(node: ast.AST, sym: _Symbols) -> str:
    for cand in _path_candidates(node, sym):
        if _classify_path_value(cand) == "cred":
            return "cred"
        if cand.lower().strip("/. ") in _CRED_FILENAME_TOKENS:
            return "cred"
    return "file"


def _func_returns(node: ast.FunctionDef) -> list[ast.expr]:
    """Return expressions of one function, not descending into
    nested function definitions."""
    out: list[ast.expr] = []

    def visit(stmt: ast.AST) -> None:
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.Lambda)):
                continue
            if isinstance(child, ast.Return) and child.value is not None:
                out.append(child.value)
            visit(child)

    for stmt in node.body:
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            out.append(stmt.value)
        visit(stmt)
    return out


def _taint_findings(tree: ast.AST, sym: _Symbols, rel: str, add,
                    note=None) -> None:
    """TAINTED_SEND (BLOCK) / SECRET_FLOW (CAUTION) for one file.
    Best-effort and self-contained: any internal failure degrades to
    no taint findings for the file (the line/AST rules still stand),
    but the degradation is RECORDED via `note` — a silently disabled
    taint layer would let one crafted deep expression hide a
    textbook exfiltration (audit F2)."""
    try:
        _taint_findings_inner(tree, sym, rel, add)
    except (RecursionError, MemoryError):
        if note is not None:
            note(Skipped(rel, "taint analysis skipped: expression "
                              "nesting too deep", True))


# Taint values are {kind: {origin, ...}} maps. Kinds: "cred",
# "envsecret", "env", "file", "input"; origins are short human
# descriptions ("read of ~/.ssh/id_rsa") carried into the finding's
# evidence (audit F13). While a function body is analysed, its
# parameters carry pseudo-kinds "param:<i>" so summaries can record
# which parameters reach the return value.
#
# The tracker is SCOPE-AWARE and FLOW-SENSITIVE within a scope
# (audit F1): bindings live per function (module scope separate),
# statements are processed in order, and a plain reassignment KILLS
# the previous taint of that name — `tok = read_token(); tok =
# 'newsletter'; send(tok)` sends the literal, and a BLOCK verdict
# must never rest on a bare-name collision between two functions.
# Container WRITES are bindings too (red team rt14/rt15/rt16):
# subscript stores, append/extend/update/setdefault/insert/add and
# setattr all taint the container object. There is still NO
# sanitiser modelling, and an unknown METHOD call propagates its
# receiver's taint (rt17/F3): `.strip()`, `.hex()`, … do not clean
# a credential.

_TAINT_MUTATORS = {"append", "extend", "update", "setdefault",
                   "insert", "add"}


def _taint_merge(a: dict, b: dict) -> dict:
    out = {k: set(v) for k, v in a.items()}
    for k, v in b.items():
        if k in out:
            out[k].update(v)
        else:
            out[k] = set(v)
    return out


def _taint_findings_inner(tree: ast.AST, sym: _Symbols, rel: str,
                          add) -> None:
    func_nodes: list = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_nodes.append(node)

    def locals_of(fn) -> set:
        names = {a.arg for a in fn.args.args}
        names |= {a.arg for a in fn.args.kwonlyargs}
        if fn.args.vararg:
            names.add(fn.args.vararg.arg)
        if fn.args.kwarg:
            names.add(fn.args.kwarg.arg)
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Name) \
                    and isinstance(sub.ctx, ast.Store):
                names.add(sub.id)
        return names

    def globals_of(fn) -> set:
        out: set = set()
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Global):
                out.update(sub.names)
        return out

    # summaries: name -> ({kind: origins} from the function's own
    # sources, {param indices that reach the return value})
    summaries: dict[str, tuple[dict, set]] = {}
    module_env: dict[str, dict] = {}

    def process_scope(body, fn, emit: bool):
        """Process one scope's statements in order. Returns
        (return_taint, env). With emit=True, sink findings are
        added via `add`."""
        is_module = fn is None
        locals_set = set() if is_module else locals_of(fn)
        globals_set = set() if is_module else globals_of(fn)
        env: dict[str, dict] = {} if not is_module else module_env
        if is_module:
            env.clear()
        params: list[str] = []
        if fn is not None:
            params = [a.arg for a in fn.args.args]
            for i, p in enumerate(params):
                env[p] = {f"param:{i}": {""}}
            for a in fn.args.kwonlyargs:
                env[a.arg] = {}
        request_data: dict[str, dict] = {}
        return_taint: dict = {}
        # This scope's own folded string/list bindings, for path
        # classification: the file-wide symbol table is flat, so a
        # name reused in another function (a path-parts list here,
        # an empty list there) clobbers it — the scope's own binding
        # is the one a read in this scope actually sees (rt15).
        scope_strs: dict[str, str] = {}
        scope_lists: dict[str, list] = {}

        def read_key(key: str) -> dict:
            if key in env:
                return {k: set(v) for k, v in env[key].items()}
            if not is_module:
                base = key.split(".", 1)[0]
                if base not in locals_set or key in module_env:
                    if key in module_env:
                        return {k: set(v)
                                for k, v in module_env[key].items()}
            return {}

        def write_key(key: str, value: dict, kill: bool) -> None:
            base = key.split(".", 1)[0]
            target = env
            if not is_module and base in globals_set \
                    and "." not in key:
                target = module_env
            if kill:
                target[key] = {k: set(v) for k, v in value.items()}
            else:
                target[key] = _taint_merge(target.get(key, {}), value)

        def expr_taint(node) -> dict:
            if node is None:
                return {}
            if isinstance(node, ast.Name):
                return read_key(node.id)
            if isinstance(node, ast.Attribute):
                dotted = _raw_dotted(node)
                if dotted:
                    t = read_key(dotted)
                    if t:
                        return t
                return expr_taint(node.value)
            if isinstance(node, ast.Constant):
                return {}
            if isinstance(node, ast.Subscript):
                if _resolve(node.value, sym) == "os.environ":
                    key = _fold_str(node.slice, sym)
                    if key and _SECRET_NAME_RE.search(key):
                        return {"envsecret":
                                {f"environment variable {key}"}}
                    return {"env": {"os.environ"}}
                return expr_taint(node.value)
            if isinstance(node, ast.Call):
                return call_taint(node)
            if isinstance(node, ast.BinOp):
                return _taint_merge(expr_taint(node.left),
                                    expr_taint(node.right))
            if isinstance(node, ast.JoinedStr):
                out: dict = {}
                for v in node.values:
                    if isinstance(v, ast.FormattedValue):
                        out = _taint_merge(out, expr_taint(v.value))
                return out
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                out = {}
                for elt in node.elts:
                    out = _taint_merge(out, expr_taint(elt))
                return out
            if isinstance(node, ast.Dict):
                out = {}
                for part in list(node.keys) + list(node.values):
                    out = _taint_merge(out, expr_taint(part))
                return out
            if isinstance(node, ast.IfExp):
                return _taint_merge(expr_taint(node.body),
                                    expr_taint(node.orelse))
            if isinstance(node, ast.BoolOp):
                out = {}
                for v in node.values:
                    out = _taint_merge(out, expr_taint(v))
                return out
            if isinstance(node, ast.UnaryOp):
                return expr_taint(node.operand)
            if isinstance(node, ast.Starred):
                return expr_taint(node.value)
            if isinstance(node, ast.Await):
                return expr_taint(node.value)
            if isinstance(node, ast.NamedExpr):
                return expr_taint(node.value)
            out = {}
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    out = _taint_merge(out, expr_taint(child))
            return out

        def read_source_taint(path_node) -> dict:
            cands = list(_path_candidates(path_node, sym))
            for sub in ast.walk(path_node):
                if isinstance(sub, ast.Subscript) \
                        and isinstance(sub.value, ast.Name) \
                        and isinstance(sub.slice, ast.Constant) \
                        and isinstance(sub.slice.value, int):
                    lst = scope_lists.get(sub.value.id)
                    if lst and 0 <= sub.slice.value < len(lst):
                        cands.append(str(lst[sub.slice.value]))
                elif isinstance(sub, ast.Name) \
                        and sub.id in scope_strs:
                    cands.append(scope_strs[sub.id])
            kind = "file"
            origin = "file read"
            for cand in cands:
                if _classify_path_value(cand) == "cred" \
                        or cand.lower().strip("/. ") \
                        in _CRED_FILENAME_TOKENS:
                    kind = "cred"
                    origin = f"read of {cand}"
                    break
            return {kind: {origin}}

        def call_taint(node: ast.Call) -> dict:
            raw = _raw_dotted(node.func)
            resolved = _resolve(node.func, sym)
            if resolved in ("os.getenv", "os.environ.get") \
                    or raw in ("getenv", "environ.get"):
                key = _fold_str(node.args[0], sym) if node.args else None
                if key and _SECRET_NAME_RE.search(key):
                    return {"envsecret":
                            {f"environment variable {key}"}}
                return {"env": {"os.environ"}}
            if raw == "input" or resolved == "input":
                return {"input": {"user input"}}
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr in ("read_text", "read_bytes"):
                    return read_source_taint(node.func.value)
                if attr == "open":
                    return read_source_taint(node.func.value)
                if attr in ("read", "readline", "readlines",
                            "encode", "decode"):
                    return expr_taint(node.func.value)
                if attr == "join":
                    return expr_taint(node.args[0]) if node.args else {}
                # Any other method call: the receiver's taint
                # propagates (no sanitiser modelling), and so does
                # an argument's — `sha256(tok).hexdigest()`,
                # `tok.strip()`, `load_token().hex()` all keep the
                # credential (rt17, audit F3).
                out = expr_taint(node.func.value)
                for arg in node.args:
                    out = _taint_merge(out, expr_taint(arg))
                for kw in node.keywords:
                    out = _taint_merge(out, expr_taint(kw.value))
                return out
            if resolved in ("open", "io.open", "codecs.open") \
                    or raw in ("open", "io.open", "codecs.open"):
                if node.args:
                    return read_source_taint(node.args[0])
                return {"file": {"file read"}}
            callee = resolved or raw
            if callee in _TAINT_WRAPPERS:
                out = {}
                for arg in node.args:
                    out = _taint_merge(out, expr_taint(arg))
                for kw in node.keywords:
                    out = _taint_merge(out, expr_taint(kw.value))
                return out
            fname = raw if raw and "." not in raw else None
            if fname and fname in summaries:
                kinds, param_map = summaries[fname]
                out = {k: set(v) for k, v in kinds.items()}
                for pos, arg in enumerate(node.args):
                    if pos in param_map:
                        out = _taint_merge(out, expr_taint(arg))
                for kw in node.keywords:
                    if kw.arg and kw.arg in params_of(fname) \
                            and params_of(fname).index(kw.arg) \
                            in param_map:
                        out = _taint_merge(out, expr_taint(kw.value))
                return out
            return {}

        def params_of(name: str) -> list:
            for fnode in func_nodes:
                if fnode.name == name:
                    return [a.arg for a in fnode.args.args]
            return []

        def bind_target(target, value_taint: dict,
                        value_node) -> None:
            if isinstance(target, ast.Name):
                write_key(target.id, value_taint, kill=True)
                if value_node is not None:
                    folded = _fold_str(value_node, sym)
                    if folded is not None:
                        scope_strs[target.id] = folded
                    lst = _fold_list(value_node, sym)
                    if lst is not None:
                        scope_lists[target.id] = lst
                if isinstance(value_node, ast.Call):
                    resolved = _resolve(value_node.func, sym)
                    raw = _raw_dotted(value_node.func)
                    if resolved == "urllib.request.Request" \
                            or raw == "Request":
                        for kw in value_node.keywords:
                            if kw.arg == "data":
                                request_data[target.id] = \
                                    expr_taint(kw.value)
            elif isinstance(target, ast.Attribute):
                dotted = _raw_dotted(target)
                if dotted:
                    write_key(dotted, value_taint, kill=True)
            elif isinstance(target, ast.Subscript):
                base = _raw_dotted(target.value)
                if base:
                    # A container write taints the container: the
                    # value can be read back out of it (rt14).
                    write_key(base, value_taint, kill=False)
            elif isinstance(target, (ast.Tuple, ast.List)):
                elts = target.elts
                values = value_node.elts if isinstance(
                    value_node, (ast.Tuple, ast.List)) \
                    and len(value_node.elts) == len(elts) else None
                for i, elt in enumerate(elts):
                    bind_target(elt,
                                expr_taint(values[i]) if values
                                else value_taint,
                                values[i] if values else value_node)
            elif isinstance(target, ast.Starred):
                bind_target(target.value, value_taint, value_node)

        def apply_effects(stmt) -> None:
            """Container mutations and walrus bindings anywhere in
            one statement (rt14/rt15/rt16, audit F13)."""
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    f = sub.func
                    if isinstance(f, ast.Attribute) \
                            and f.attr in _TAINT_MUTATORS:
                        base = _raw_dotted(f.value)
                        if base:
                            t: dict = {}
                            for a in sub.args:
                                t = _taint_merge(t, expr_taint(a))
                            for kw in sub.keywords:
                                t = _taint_merge(t,
                                                 expr_taint(kw.value))
                            write_key(base, t, kill=False)
                    elif isinstance(f, ast.Name) and f.id == "setattr" \
                            and len(sub.args) >= 3 \
                            and isinstance(sub.args[1], ast.Constant) \
                            and isinstance(sub.args[1].value, str):
                        base = _raw_dotted(sub.args[0])
                        if base:
                            t = expr_taint(sub.args[2])
                            write_key(f"{base}.{sub.args[1].value}",
                                      t, kill=False)
                            write_key(base, t, kill=False)
                elif isinstance(sub, ast.NamedExpr) \
                        and isinstance(sub.target, ast.Name):
                    write_key(sub.target.id,
                              expr_taint(sub.value), kill=True)

        def check_sink(node: ast.Call) -> None:
            dotted = _resolve(node.func, sym)
            raw = _raw_dotted(node.func)
            if not dotted and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Call):
                ctor = _resolve(node.func.value.func, sym)
                if ctor.endswith("Session"):
                    dotted = ("requests." if ctor.startswith("requests")
                              else "httpx.") + node.func.attr
            module = dotted.split(".")[0] if dotted else ""
            method = dotted.rsplit(".", 1)[-1] if dotted else ""
            body: dict = {}
            header: dict = {}
            is_sink = False
            if module in ("requests", "httpx", "aiohttp") \
                    and (method in _SEND_METHODS or method == "request"):
                is_sink = True
                for arg in node.args[1:]:
                    body = _taint_merge(body, expr_taint(arg))
                for kw in node.keywords:
                    if kw.arg in ("data", "json", "params", "files"):
                        body = _taint_merge(body, expr_taint(kw.value))
                    elif kw.arg in ("headers", "auth"):
                        header = _taint_merge(header,
                                              expr_taint(kw.value))
            elif dotted.startswith("urllib.request") \
                    and method == "urlopen":
                if node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Name) \
                            and first.id in request_data:
                        is_sink = True
                        body = _taint_merge(body,
                                            request_data[first.id])
                    elif isinstance(first, ast.Call):
                        for kw in first.keywords:
                            if kw.arg == "data":
                                is_sink = True
                                body = _taint_merge(body,
                                                    expr_taint(kw.value))
            elif dotted.startswith("http.client") \
                    and method in ("request", "putrequest",
                                   "endheaders"):
                is_sink = True
                if len(node.args) >= 3:
                    body = _taint_merge(body, expr_taint(node.args[2]))
                for kw in node.keywords:
                    if kw.arg == "body":
                        body = _taint_merge(body, expr_taint(kw.value))
                    elif kw.arg == "headers":
                        header = _taint_merge(header,
                                              expr_taint(kw.value))
            elif isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("send", "sendall", "sendto"):
                is_sink = True
                if node.args:
                    body = _taint_merge(body, expr_taint(node.args[0]))
            elif dotted.startswith("smtplib.") \
                    and method in ("sendmail", "send_message"):
                is_sink = True
                for arg in node.args:
                    body = _taint_merge(body, expr_taint(arg))
                for kw in node.keywords:
                    body = _taint_merge(body, expr_taint(kw.value))
            if not is_sink:
                return
            cred_origins = sorted(
                (body.get("cred") or set())
                | (header.get("cred") or set()))
            if cred_origins:
                origin = cred_origins[0] if cred_origins[0] else \
                    "a credential source"
                add("TAINTED_SEND", rel, node.lineno,
                    f"credential value from {origin} reaches a "
                    f"network send")
            elif "envsecret" in body:
                origins = sorted(o for o in body["envsecret"] if o)
                origin = origins[0] if origins else \
                    "an environment variable"
                add("SECRET_FLOW", rel, node.lineno,
                    f"secret value from {origin} is sent in a "
                    f"request body")

        def visit_stmt(stmt) -> None:
            nonlocal return_taint
            if isinstance(stmt, (ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
                return  # separate scopes, processed on their own
            if isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    return_taint = _taint_merge(
                        return_taint, expr_taint(stmt.value))
                return
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    apply_effects(item.context_expr)
                    if isinstance(item.optional_vars, ast.Name):
                        write_key(item.optional_vars.id,
                                  expr_taint(item.context_expr),
                                  kill=True)
                for sub in stmt.body:
                    visit_stmt(sub)
                return
            if isinstance(stmt, ast.If):
                apply_effects(stmt.test)
                saved = {k: {kk: set(vv) for kk, vv in v.items()}
                         for k, v in env.items()}
                for sub in stmt.body:
                    visit_stmt(sub)
                body_env = {k: {kk: set(vv) for kk, vv in v.items()}
                            for k, v in env.items()}
                env.clear()
                env.update(saved)
                for sub in stmt.orelse:
                    visit_stmt(sub)
                for key, val in body_env.items():
                    env[key] = _taint_merge(env.get(key, {}), val)
                return
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                apply_effects(stmt.iter)
                bind_target(stmt.target, expr_taint(stmt.iter),
                            stmt.iter)
                saved = {k: {kk: set(vv) for kk, vv in v.items()}
                         for k, v in env.items()}
                for sub in stmt.body:
                    visit_stmt(sub)
                for key, val in list(env.items()):
                    saved[key] = _taint_merge(saved.get(key, {}), val)
                env.clear()
                env.update(saved)
                for sub in stmt.orelse:
                    visit_stmt(sub)
                return
            if isinstance(stmt, ast.While):
                apply_effects(stmt.test)
                for sub in stmt.body:
                    visit_stmt(sub)
                for sub in stmt.orelse:
                    visit_stmt(sub)
                return
            if isinstance(stmt, ast.Try) or type(stmt).__name__ == \
                    "TryStar":
                saved = {k: {kk: set(vv) for kk, vv in v.items()}
                         for k, v in env.items()}
                for sub in stmt.body:
                    visit_stmt(sub)
                body_env = {k: {kk: set(vv) for kk, vv in v.items()}
                            for k, v in env.items()}
                env.clear()
                env.update(saved)
                for handler in stmt.handlers:
                    for sub in handler.body:
                        visit_stmt(sub)
                for key, val in body_env.items():
                    env[key] = _taint_merge(env.get(key, {}), val)
                for sub in stmt.orelse + stmt.finalbody:
                    visit_stmt(sub)
                return
            # Simple statement: mutation effects first (they are
            # additive), then sinks judge the statement's calls with
            # bindings as they stand, then the statement's own
            # bindings land (a reassignment kills prior taint).
            apply_effects(stmt)
            if emit:
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Call):
                        check_sink(sub)
            if isinstance(stmt, ast.Assign):
                value_taint = expr_taint(stmt.value)
                for target in stmt.targets:
                    bind_target(target, value_taint, stmt.value)
            elif isinstance(stmt, ast.AnnAssign) \
                    and stmt.value is not None:
                bind_target(stmt.target, expr_taint(stmt.value),
                            stmt.value)
            elif isinstance(stmt, ast.AugAssign):
                current = expr_taint(stmt.target)
                merged = _taint_merge(current,
                                      expr_taint(stmt.value))
                bind_target(stmt.target, merged, stmt.value)

        for stmt in body:
            visit_stmt(stmt)
        return return_taint, env

    # Fixpoint over function summaries (bounded rounds), then one
    # final pass with sink emission on the converged summaries.
    for _round in range(5):
        changed = False
        process_scope(tree.body, None, emit=False)
        for fnode in func_nodes:
            ret, _env = process_scope(fnode.body, fnode, emit=False)
            kinds = {k: v for k, v in ret.items()
                     if not k.startswith("param:")}
            param_map = {int(k.split(":", 1)[1]) for k in ret
                         if k.startswith("param:")}
            new_summary = (kinds, param_map)
            if summaries.get(fnode.name) != new_summary:
                summaries[fnode.name] = new_summary
                changed = True
        if not changed:
            break
    process_scope(tree.body, None, emit=True)
    for fnode in func_nodes:
        process_scope(fnode.body, fnode, emit=True)


def _ast_findings(path: Path, rel: str, text: str, add, flags: dict,
                  note=None) -> set[int]:
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
    except (RecursionError, MemoryError):
        # A crafted deep expression defeats the parser itself; the
        # AST layer (taint included) is off for this file and that
        # must be RECORDED, not silent (audit F2).
        if note is not None:
            note(Skipped(rel, "python AST analysis skipped: "
                              "nesting too deep", True))
        return metadata_send_lines
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
        elif dotted.startswith("urllib.request") or dotted == "urlopen":
            # urllib.request only: urllib.parse (urlparse, quote,
            # urlencode) manipulates URL strings — it never touches
            # the network (FP fixtures 40/41/44).
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
    # v0.5 taint-lite: credential/env-secret value flow to sends.
    _taint_findings(tree, sym, rel, add, note=note)
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
# Behaviour means the module is USED (imported or called), not merely
# NAMED: "requests" as a string inside install_requires is metadata
# declaration, and flagging it made every dependency-declaring
# setup.py an install-script finding. subprocess / os.system words
# only ever appear as usage, so they stay bare. urllib counts only
# as urllib.request — urllib.parse is string handling, not network
# (audit F6) — and the pass runs on comment- AND string-stripped
# code, because a docstring example is documentation, not behaviour.
_SETUP_BEHAVIOUR_RE = re.compile(
    r"(subprocess|os\.system|os\.popen|check_output|check_call|"
    r"(?:import|from)\s+(?:requests|httpx|socket)\b|"
    r"urllib\.request\b|"
    r"(?:requests|httpx|socket)\s*\.)")
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


def _py_inert_regions(text: str):
    """(comment_cols, string_spans) for a Python source text, from
    tokenize: comment_cols maps a line number to the column where its
    comment starts; string_spans maps a line number to the column
    ranges covered by string literals on that line. Both describe
    INERT text — prose and data, not executed code. Returns two empty
    dicts when the file cannot be tokenised; callers then treat
    everything as live, exactly as before."""
    comment_cols: dict[int, int] = {}
    string_spans: dict[int, list[tuple[int, int]]] = {}
    str_types = {tokenize.STRING}
    for attr in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
        t = getattr(tokenize, attr, None)
        if t is not None:
            str_types.add(t)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                comment_cols[tok.start[0]] = tok.start[1]
            elif tok.type in str_types:
                (r1, c1), (r2, c2) = tok.start, tok.end
                for row in range(r1, r2 + 1):
                    lo = c1 if row == r1 else 0
                    hi = c2 if row == r2 else 1 << 30
                    string_spans.setdefault(row, []).append((lo, hi))
    except Exception:
        return {}, {}
    return comment_cols, string_spans


def _blank_spans(lines: list[str],
                 spans_by_line: dict[int, list[tuple[int, int]]]
                 ) -> list[str]:
    """Blank the given column ranges in each line (positions and
    line count preserved)."""
    if not spans_by_line:
        return lines
    out = []
    for i, line in enumerate(lines, start=1):
        spans = spans_by_line.get(i)
        if not spans:
            out.append(line)
            continue
        chars = list(line)
        for lo, hi in spans:
            for j in range(lo, min(hi, len(chars))):
                chars[j] = " "
        out.append("".join(chars))
    return out


def _strip_py_strings(text: str) -> str:
    """Blank out Python string-literal content (positions preserved),
    on top of comment stripping: docstrings and data strings are not
    behaviour. Falls back to comment-stripped text when the file
    cannot be tokenised."""
    code = _strip_py_comments(text)
    _, string_spans = _py_inert_regions(code)
    if not string_spans:
        return code
    return "\n".join(_blank_spans(code.split("\n"), string_spans))


_SHELL_TOKEN_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|\\.")


def _shell_comment_col(line: str) -> int | None:
    """Column where a shell '#' comment starts on this line, or None.
    A '#' only opens a comment at a word boundary (line start, or
    after whitespace / a command separator) and outside quotes."""
    i = 0
    while i < len(line):
        ch = line[i]
        if ch in "'\"\\":
            m = _SHELL_TOKEN_RE.match(line, i)
            i = m.end() if m else i + 1
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t;|&("):
            return i
        i += 1
    return None


def _js_inert_regions(lines: list[str]):
    """(comment_spans, string_spans) for JS/TS source lines, from a
    small state machine (line/block comments; ', \" and ` strings).
    Template-literal ${} nesting is treated as string throughout —
    an approximation that only ever widens the inert set inside
    templates."""
    comment_spans: dict[int, list[tuple[int, int]]] = {}
    string_spans: dict[int, list[tuple[int, int]]] = {}
    state = None  # None | "line" | "block" | "'" | '"' | "`"
    span_start = None
    for lineno, line in enumerate(lines, start=1):
        i = 0
        while i < len(line):
            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""
            if state == "line":
                i = len(line)
                comment_spans.setdefault(lineno, []).append(
                    (span_start, len(line)))
                span_start = None
                state = None
                break
            if state == "block":
                if ch == "*" and nxt == "/":
                    comment_spans.setdefault(lineno, []).append(
                        (span_start, i + 2))
                    span_start = None
                    state = None
                    i += 2
                    continue
                i += 1
                continue
            if state in ("'", '"', "`"):
                if ch == "\\":
                    i += 2
                    continue
                if ch == state:
                    string_spans.setdefault(lineno, []).append(
                        (span_start, i + 1))
                    span_start = None
                    state = None
                i += 1
                continue
            # code state
            if ch == "/" and nxt == "/":
                state = "line"
                span_start = i
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                span_start = i
                i += 2
                continue
            if ch in ("'", '"', "`"):
                state = ch
                span_start = i
                i += 1
                continue
            i += 1
        if state == "line":
            comment_spans.setdefault(lineno, []).append(
                (span_start, len(line)))
            state = None
        elif state == "block" and span_start is not None:
            comment_spans.setdefault(lineno, []).append(
                (span_start, len(line)))
            span_start = 0
        elif state in ("'", '"') :
            state = None  # unterminated ' or " string ends at EOL
        elif state == "`" and span_start is not None:
            string_spans.setdefault(lineno, []).append(
                (span_start, len(line)))
            span_start = 0
    return comment_spans, string_spans


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


# Routine lifecycle commands: build/tooling steps that run on
# millions of honest installs. Their PRESENCE is still a caution
# (an install hook exists), but they are not install-time EXECUTION
# evidence for the DEPENDENCY_EXECUTION combination — a TypeScript
# compile is not a payload runner (audit F2).
_ROUTINE_SEGMENT_RE = re.compile(
    r"^(?:npx\s+)?tsc\b|^patch-package\b|^husky\b|"
    r"^node-gyp\s+rebuild\b|^git\s+(?:describe|rev-parse)\b|"
    r"^node\s+--version\b")


def _lifecycle_command_routine(command: str) -> bool:
    segs = [s.strip() for s in re.split(r"&&|\|\||;", command)
            if s.strip()]
    return bool(segs) and all(
        _ROUTINE_SEGMENT_RE.search(s) for s in segs)


_SUBPROCESS_CALL_RE = re.compile(
    r"subprocess\s*\.\s*\w+\s*\(|os\.(?:system|popen)\s*\(|"
    r"check_output\s*\(|check_call\s*\(")
_GIT_VERSION_CALL_RE = re.compile(
    r"[\"']git[\"']\s*,\s*[\"'](?:describe|rev-parse)[\"']|"
    r"[\"']git\s+(?:describe|rev-parse)\b")


def _install_evidence_routine(evidence: str) -> bool:
    """True when a PACKAGE_INSTALL_SCRIPT finding's evidence is a
    routine build/tooling action rather than install-time execution:
    a routine npm lifecycle command, or a setup.py that only reads
    its version from git (subprocess + git describe / rev-parse)."""
    ev = evidence.strip()
    if _lifecycle_command_routine(ev):
        return True
    if "subprocess" in ev and re.search(
            r"[\"']git[\"']\s*,\s*[\"'](?:describe|rev-parse)[\"']", ev):
        return True
    return bool(re.search(
        r"(?:os\.popen|check_output)\s*\(\s*[\"']git\s+"
        r"(?:describe|rev-parse)", ev))


_NPM_SCRIPT_LINE_RE = re.compile(
    r'"(preinstall|install|postinstall|prepare|prepublish|prepack|'
    r'postpack)"\s*:\s*"((?:[^"\\]|\\.)*)"')


# A template manifest (package.template.json / package.json.template)
# is a package.json in waiting — scaffolding skills instantiate it
# verbatim — so it gets the same install-script and dependency-source
# analysis as the real name.
_PACKAGE_JSON_NAMES = {"package.json", "package.template.json",
                       "package.json.template"}


def _package_findings(rel: str, path: Path, text: str, lines: list[str],
                      add, root: Path, note=None) -> None:
    def classify_lifecycle(line: int, command: str) -> None:
        if any(p.match(command.strip()) for p in _BENIGN_LIFECYCLE_RES):
            return  # node-gyp rebuild / husky: standard, benign
        add("PACKAGE_INSTALL_SCRIPT", rel, line, command)
        if _INSTALL_EXEC_RE.search(command) or _referenced_js_exec(
                path.parent, root, command):
            add("PACKAGE_INSTALL_SCRIPT_EXEC", rel, line, command)
        if _ENV_INJECT_SET_RE.search(command):
            add("ENV_INJECTION_INSTALL", rel, line, command)

    if path.name in _PACKAGE_JSON_NAMES:
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if data is None:
            if note is not None:
                note(Skipped(rel, "malformed package.json — "
                                  "install-script analysis skipped", True))
            # A malformed manifest is not a blind spot: run the
            # lifecycle analysis over the raw script lines (the
            # parsed path above cannot run) — red-team d5.
            for lineno, raw in enumerate(lines, start=1):
                m = _NPM_SCRIPT_LINE_RE.search(raw)
                if m:
                    command = m.group(2).replace('\\"', '"') \
                        .replace("\\\\", "\\")
                    if command.strip():
                        classify_lifecycle(lineno, command)
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
            classify_lifecycle(_find_line(lines, f'"{key}"'), command)
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
        behaviour = _strip_py_strings(text)
        for lineno, line in enumerate(behaviour.splitlines(), start=1):
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
                        _strip_py_strings(module_text)):
                    hit_line = code[:m.start()].count("\n") + 1
                    break
        if hit_line is not None:
            # The evidence must show what the install-time code DOES,
            # not the first import that tripped the behaviour scan:
            # the combination check reads it to tell a git-describe
            # version read (routine) from running a program. Prefer
            # the first NON-routine subprocess call line; only when
            # every call is a git version read does the routine line
            # become the evidence (audit P2).
            call_lines = [
                (i, raw_line)
                for i, raw_line in enumerate(lines, start=1)
                if _SUBPROCESS_CALL_RE.search(raw_line)]
            if call_lines:
                bad = [c for c in call_lines
                       if not _GIT_VERSION_CALL_RE.search(c[1])]
                hit_line, evidence = (bad[0] if bad
                                      else call_lines[0])
            else:
                evidence = lines[hit_line - 1] \
                    if 0 < hit_line <= len(lines) else ""
            add("PACKAGE_INSTALL_SCRIPT", rel, hit_line, evidence)


# --------------------------------------------------------------------------
# Dependency manifests: where do declared dependencies come from?
# --------------------------------------------------------------------------
#
# A declared dependency is only as reviewed as its source. Registry
# artefacts are versioned and independently scanned; a dependency
# sourced from a git URL, a direct archive link, a local path, or a
# non-official index can change silently and bypasses all of that.
# These checks are purely structural: WHERE each declared dependency
# comes from, never what it is called. (Name-similarity / typosquat
# guessing is deliberately NOT done — a fixed list of "top packages"
# plus edit distance has real false-positive risk against the long
# tail of legitimate names, and the benchmark corpus contains no
# manifest-declared typosquat shape to validate it against.)

_OFFICIAL_INDEX_HOSTS = {"pypi.org", "www.pypi.org",
                         "files.pythonhosted.org"}


def _spec_is_off_registry(spec: str) -> bool:
    """True for an npm-style dependency spec that bypasses the
    registry: git URL, direct http(s) link, or local file path."""
    low = spec.strip().lower()
    return low.startswith((
        "git+", "git://", "ssh://", "github:", "gitlab:", "bitbucket:",
        "gist:", "http://", "https://", "file:", "link:", "portal:"))


def _index_url_off_registry(url: str) -> bool:
    authority = re.sub(r"^https?://", "", url.strip().strip("\"'").lower())
    authority = authority.split("/")[0]
    # Userinfo (user:pass@host) — the host is what follows the LAST @.
    host = authority.rsplit("@", 1)[-1].split(":")[0]
    return bool(host) and host not in _OFFICIAL_INDEX_HOSTS


_DIRECT_REF_URL_RE = re.compile(r"@\s*(?:https?://|file:|git\+)")
_DIRECT_REF_NAME_RE = re.compile(r"[\w.\-]+[ \t]*$")


def _direct_reference_hit(text: str) -> int | None:
    """Offset of a PEP 508 direct reference (``name @ URL``), or None.

    Written as a scan, not a single regex: the natural pattern
    ``[\\w.-]+\\s*@\\s*URL`` is O(n^2) on a long word-character run
    (every start position re-scans the run), and a 300 KB setup.py
    hung the scanner with it (audit F1). Here the URL side is found
    first (cheap literal anchor), then the name is verified with a
    bounded look-back on the same line — linear overall."""
    for m in _DIRECT_REF_URL_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[max(line_start, m.start() - 100):m.start()]
        name = _DIRECT_REF_NAME_RE.search(prefix)
        if name:
            return max(line_start, m.start() - 100) + name.start()
    return None


def _blank_full_line_comments(text: str) -> str:
    """Blank lines whose first non-space character is '#' (positions
    and line numbers preserved). Manifest formats (TOML / Pipfile)
    use '#' comments; a pattern mentioned inside one is prose about
    the pattern, not a declaration (audit F9)."""
    return "\n".join(
        " " * len(line) if line.lstrip().startswith("#") else line
        for line in text.split("\n"))


def _requirements_off_registry(line: str) -> bool:
    """One requirements-file line: does it source a package outside
    the official registry (git / direct URL / off-registry index /
    editable install of a non-self path)?"""
    code = line.strip()
    if not code or code.startswith("#"):
        return False
    low = code.lower()
    if "git+" in low or "git://" in low:
        return True
    if re.search(r"@\s*(https?://|file:)", low):
        return True  # PEP 508 direct reference: name @ URL
    if low.startswith(("http://", "https://")):
        return True  # a bare URL line is a direct archive reference
    for flag in ("--index-url", "--extra-index-url", "-i"):
        m = re.search(re.escape(flag) + r"(?:\s+|=)(\S+)", code)
        if m and _index_url_off_registry(m.group(1)):
            return True
    m = re.match(r"(?:-e|--editable)\s+(\S+)", code)
    if m and m.group(1) not in (".", "./"):
        # An editable install of anything but the project itself is a
        # local-path (or URL, handled above) dependency.
        return True
    return False


_PYPROJECT_OFF_REGISTRY_RES = [
    # Poetry-style inline source table: {git = "..."} / {url = ...} /
    # {path = ...} as any key of the table.
    re.compile(r"\{[^{}]*\b(?:git|url|path)\s*="),
    # A declared extra package source replaces / supplements the
    # official index for the whole project.
    re.compile(r"\[\[?\s*tool\.poetry\.source\s*\]\]?"),
]
_SETUP_OFF_REGISTRY_RES = [
    re.compile(r"git\+https?://"),
    re.compile(r"dependency_links\s*=\s*\[[^\]]*https?://", re.DOTALL),
]
_PIPFILE_OFF_REGISTRY_RES = [
    re.compile(r"\{[^{}]*\b(?:git|file|path)\s*="),
    re.compile(r"^\s*(?:git|file)\s*=", re.MULTILINE),
]

_FOLD_STR_RE = re.compile(
    r"([\"'])((?:\\.|(?!\1)[^\\\n])*)\1[ \t]*\+[ \t]*"
    r"([\"'])((?:\\.|(?!\3)[^\\\n])*)\3")


def _fold_adjacent_strings(text: str) -> str:
    """Join adjacent string literals concatenated with '+' on one
    line ("helperpkg @ " + "https://…") so pattern checks see the
    value Python would build. Same-line only, so line numbers in the
    folded text still match the original."""
    for _ in range(8):
        folded = _FOLD_STR_RE.sub(
            lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1),
            text)
        if folded == text:
            break
        text = folded
    return text


def _iter_dep_specs(deps: dict):
    """(name, spec) pairs from a dependency mapping, descending one
    level into nested tables (npm overrides nest by design)."""
    for dep_name, spec in deps.items():
        if isinstance(spec, str):
            yield dep_name, spec
        elif isinstance(spec, dict):
            for sub_name, sub_spec in spec.items():
                if isinstance(sub_spec, str):
                    yield f"{dep_name}>{sub_name}", sub_spec


def _dependency_findings(rel: str, path: Path, text: str,
                         lines: list[str], add) -> None:
    """Structural source check over the dependency manifests in the
    folder. Fires DEPENDENCY_SOURCE (caution) per manifest that
    declares at least one off-registry dependency; the scan-level
    combination in scan_folder escalates to DEPENDENCY_EXECUTION when
    install-time execution is also present."""
    name = path.name
    low_name = name.lower()
    if name in _PACKAGE_JSON_NAMES:
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if data is None:
            # Malformed JSON: the parse-based pass in
            # _package_findings already recorded the coverage gap,
            # but a broken manifest must not become a blind spot —
            # fall back to a raw-text scan of its "name": "spec"
            # pairs (red-team d5).
            for lineno, line in enumerate(lines, start=1):
                for m in re.finditer(r'"[^"\n]+"\s*:\s*"([^"\n]*)"',
                                     line):
                    if _spec_is_off_registry(m.group(1)):
                        add("DEPENDENCY_SOURCE", rel, lineno, line)
                        return
            return
        if not isinstance(data, dict):
            return
        for section in ("dependencies", "devDependencies",
                        "optionalDependencies", "peerDependencies",
                        "bundledDependencies", "bundleDependencies",
                        "overrides", "resolutions"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name, spec in _iter_dep_specs(deps):
                if _spec_is_off_registry(spec):
                    add("DEPENDENCY_SOURCE", rel,
                        _find_line(lines, f'"{dep_name.split(">")[0]}"'),
                        f"{dep_name}: {spec}")
                    return
    elif low_name.startswith("requirements") and low_name.endswith(".txt"):
        for lineno, line in enumerate(lines, start=1):
            if _requirements_off_registry(line):
                add("DEPENDENCY_SOURCE", rel, lineno, line)
                return
        # Follow -r / --requirement includes ONE level: an included
        # file is a manifest too, whatever it is named (red-team d2).
        for line in lines:
            m = re.match(r"\s*(?:-r|--requirement)\s+(\S+)", line)
            if not m:
                continue
            inc = (path.parent / m.group(1)).resolve()
            try:
                inc.relative_to(path.parent.resolve())
            except ValueError:
                continue  # include escapes the package dir: not followed
            try:
                inc_text = _decode(inc.read_bytes()[:MAX_FILE_BYTES])
            except OSError:
                continue
            if inc_text is None:
                continue
            inc_rel = (rel.rpartition("/")[0] + "/" if "/" in rel
                       else "") + m.group(1)
            for inc_lineno, inc_line in enumerate(
                    inc_text.splitlines(), start=1):
                if _requirements_off_registry(inc_line):
                    add("DEPENDENCY_SOURCE", inc_rel, inc_lineno,
                        inc_line)
                    return
    elif name == "pyproject.toml":
        code = _blank_full_line_comments(text)
        hit = _direct_reference_hit(code)
        if hit is not None:
            line_no = code[:hit].count("\n") + 1
            add("DEPENDENCY_SOURCE", rel, line_no,
                lines[line_no - 1] if 0 < line_no <= len(lines) else "")
            return
        for pattern in _PYPROJECT_OFF_REGISTRY_RES:
            m = pattern.search(code)
            if m:
                line_no = code[:m.start()].count("\n") + 1
                add("DEPENDENCY_SOURCE", rel, line_no,
                    lines[line_no - 1] if 0 < line_no <= len(lines) else "")
                return
    elif name == "setup.py":
        code = _fold_adjacent_strings(_strip_py_comments(text))
        hit = _direct_reference_hit(code)
        if hit is not None:
            line_no = code[:hit].count("\n") + 1
            add("DEPENDENCY_SOURCE", rel, line_no,
                lines[line_no - 1] if 0 < line_no <= len(lines) else "")
            return
        for pattern in _SETUP_OFF_REGISTRY_RES:
            m = pattern.search(code)
            if m:
                line_no = code[:m.start()].count("\n") + 1
                add("DEPENDENCY_SOURCE", rel, line_no,
                    lines[line_no - 1] if 0 < line_no <= len(lines) else "")
                return
    elif name == "Pipfile":
        code = _blank_full_line_comments(text)
        for pattern in _PIPFILE_OFF_REGISTRY_RES:
            m = pattern.search(code)
            if m:
                line_no = code[:m.start()].count("\n") + 1
                add("DEPENDENCY_SOURCE", rel, line_no,
                    lines[line_no - 1] if 0 < line_no <= len(lines) else "")
                return
        # A [[source]] block pointing anywhere but the official index
        # (single-quoted URLs are valid TOML too — red-team d4).
        for m in re.finditer(r"url\s*=\s*[\"'](https?://[^\"']+)[\"']",
                             code):
            if _index_url_off_registry(m.group(1)):
                line_no = code[:m.start()].count("\n") + 1
                add("DEPENDENCY_SOURCE", rel, line_no,
                    lines[line_no - 1] if 0 < line_no <= len(lines) else "")
                return


# --- v0.5 offline typosquat check (design §4) ------------------------------
# Declared dependency names vs a curated core list of top package
# names per ecosystem, shipped as data files (skillscan/toplists/),
# loaded exactly like phrases/. CAUTION only, never combined into
# DEPENDENCY_EXECUTION. Distances use optimal-string-alignment
# Damerau-Levenshtein (adjacent transposition costs 1).

_TOPLIST_CACHE: dict[str, dict] = {}


def _load_toplist(ecosystem: str) -> dict:
    if ecosystem not in _TOPLIST_CACHE:
        data: dict = {"top_names": [], "known_legit_neighbours": []}
        try:
            raw = json.loads((Path(__file__).parent / "toplists"
                              / f"{ecosystem}.json").read_text(
                                  encoding="utf-8"))
            if isinstance(raw, dict):
                data = raw
        except (OSError, ValueError):
            pass
        # Normalised forms are computed once, here — a manifest can
        # declare thousands of names and must not re-normalise the
        # whole list per name.
        data["_tops_norm"] = [_normalize_dep_name(t, ecosystem)
                              for t in data.get("top_names", [])]
        data["_neighbours_norm"] = {
            _normalize_dep_name(n, ecosystem)
            for n in data.get("known_legit_neighbours", [])}
        # (name, separator-stripped name, char counts) triples,
        # precomputed: a manifest with thousands of deps must not
        # re-derive these per declared name.
        data["_tops_pairs"] = [
            (t, re.sub(r"[-_.]", "", t), _char_counts(t), rank)
            for rank, t in enumerate(data["_tops_norm"])]
        _TOPLIST_CACHE[ecosystem] = data
    return _TOPLIST_CACHE[ecosystem]


def _char_counts(s: str) -> dict:
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return counts


def _normalize_dep_name(name: str, ecosystem: str) -> str:
    name = name.strip().strip("\"'").lower()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name)
    return name


def _dl_distance(a: str, b: str, cap: int = 2) -> int:
    """OSA Damerau-Levenshtein with an early-exit cap."""
    la, lb = len(a), len(b)
    if abs(la - lb) > cap:
        return cap + 1
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev2: list[int] | None = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        best = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            value = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (prev2 is not None and j > 1
                    and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                value = min(value, prev2[j - 2] + 1)
            cur[j] = value
            best = min(best, value)
        if best > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[lb]


_CYRILLIC_FOLD = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "і": "i",
    "ѕ": "s", "ј": "j", "к": "k", "м": "m",
    "н": "h", "т": "t", "в": "b", "ԁ": "d",
})


def _homoglyph_fold(name: str) -> str:
    folded = name.translate(_CYRILLIC_FOLD)
    return folded.replace("rn", "m").replace("0", "o") \
        .replace("1", "l")


def _deletes_upto2(s: str) -> set:
    """All strings reachable from `s` by deleting one or two
    characters (plus `s` itself). Two names within edit distance 2
    always share such a string — the SymSpell observation — which
    turns the per-name scan of every top name into dictionary
    lookups (audit F7)."""
    out = {s}
    singles = set()
    for i in range(len(s)):
        singles.add(s[:i] + s[i + 1:])
    out |= singles
    for t in singles:
        for i in range(len(t)):
            out.add(t[:i] + t[i + 1:])
    return out


_MATCH_INDEX_CACHE: dict = {}


def _match_index(tops: list) -> dict:
    """Deletion index over the top names, built once per tops list
    (keyed by identity, with a strong reference kept so the id
    cannot be recycled)."""
    key = id(tops)
    cached = _MATCH_INDEX_CACHE.get(key)
    if cached is not None and cached[0] is tops:
        return cached[1]
    pairs = []
    for idx, t in enumerate(tops):
        if isinstance(t, str):
            pairs.append((t, re.sub(r"[-_.]", "", t), idx))
        else:
            pairs.append((t[0], t[1], idx))
    exact = set()
    by_squashed: dict[str, str] = {}
    deletes: dict[str, set] = {}
    rank: dict[str, int] = {}
    for top, squashed, idx in pairs:
        exact.add(top)
        rank[top] = idx
        by_squashed.setdefault(squashed, top)
        if len(top) <= 40:
            for variant in _deletes_upto2(top):
                deletes.setdefault(variant, set()).add(top)
    index = {"exact": exact, "by_squashed": by_squashed,
             "deletes": deletes, "rank": rank}
    _MATCH_INDEX_CACHE[key] = (tops, index)
    return index


def _typosquat_match(name: str, tops: list,
                     neighbours: set[str]) -> tuple[str, int] | None:
    """(top_name, distance) when `name` (already normalised) is a
    near-miss of a top package, else None. Exact matches and known
    legitimate neighbours never match. Candidate generation uses
    the deletion index; every candidate is then verified with the
    real distance function and the same prefix/rank rules as a
    direct scan, so the index changes speed, never verdicts."""
    if not name or name in neighbours:
        return None
    index = _match_index(tops)
    if name in index["exact"]:
        return None
    squashed = re.sub(r"[-_.]", "", name)
    if len(squashed) >= 4:
        top = index["by_squashed"].get(squashed)
        if top is not None and top != name:
            return (top, 1)  # separator mutation
    folded = _homoglyph_fold(name)
    if folded != name and folded in index["exact"]:
        return (folded, 1)  # homoglyph-lite
    if len(name) > 42:
        return None
    candidates: set = set()
    for variant in _deletes_upto2(name):
        candidates |= index["deletes"].get(variant, set())
    for top in sorted(candidates):
        if abs(len(name) - len(top)) > 2:
            continue
        dist = _dl_distance(name, top)
        if dist == 1:
            return (top, 1)
        if dist == 2 and name[0] == top[0]:
            prefix = 0
            for x, y in zip(name, top):
                if x != y:
                    break
                prefix += 1
            # Distance-2 needs a long shared prefix and either a
            # reasonably long name, or one of the hundred most-
            # impersonated packages: `requts` (6 chars, prefix 4)
            # aimed at requests is the canonical squat shape, and
            # the length floor alone let it through (rt20).
            if prefix >= 4 and (len(name) >= 7
                                or index["rank"].get(top, 10 ** 9)
                                < 100):
                return (top, 2)
    return None


def _typosquat_check_name(eco: str, raw_name: str, rel: str,
                          lines: list[str], add) -> bool:
    data = _load_toplist(eco)
    tops = data["_tops_pairs"]
    neighbours = data["_neighbours_norm"]
    name = _normalize_dep_name(raw_name, eco)
    hit = _typosquat_match(name, tops, neighbours)
    if not hit:
        return False
    top, dist = hit
    line_no = _find_line(lines, raw_name)
    add("TYPOSQUAT_SUSPECT", rel, line_no,
        f"{raw_name} (edit distance {dist} from '{top}')",
        severity_cap="caution")
    return True


_NAME_TOKEN = r"[A-Za-z0-9\u00c0-\uffff][A-Za-z0-9._\u00c0-\uffff-]*"
_REQ_NAME_RE = re.compile(r"^\s*(" + _NAME_TOKEN + r")")
_EGG_RE = re.compile(r"[#&]egg=(" + _NAME_TOKEN + r")")
# A quoted name followed by a specifier/extras character OR by its
# closing quote: bare unpinned names ("reqeusts", one per line) are
# a standard pyproject style, and requiring a specifier character
# blinded the PyPI half of the check to them wholesale (rt19).
_TOML_DEP_STR_RE = re.compile(
    r"[\"']([A-Za-z0-9._\u00c0-\uffff-]+)\s*"
    r"(?:[<>=!~^\[@;,]|[\"'])")
_SETUP_REQ_RE = re.compile(r"install_requires\s*=\s*\[(.*?)\]",
                           re.DOTALL)
_SETUP_NAME_RE = re.compile(r"[\"']([A-Za-z0-9._\u00c0-\uffff-]+)")
_SETUP_VAR_RE = re.compile(r"install_requires\s*=\s*([A-Za-z_][\w]*)")
_PIPFILE_SECTION_RE = re.compile(r"^\s*\[(?:dev-)?packages\]\s*$")
_PIPFILE_KEY_RE = re.compile(
    r"^\s*\"?(" + _NAME_TOKEN + r")\"?\s*=")


def _typosquat_findings(rel: str, path: Path, text: str,
                        lines: list[str], add) -> None:
    stem = path.name
    suffix = path.suffix.lower()
    if stem in _PACKAGE_JSON_NAMES:
        try:
            manifest = json.loads(text)
        except ValueError:
            return
        if not isinstance(manifest, dict):
            return
        for section in ("dependencies", "devDependencies",
                        "optionalDependencies", "peerDependencies",
                        "bundledDependencies", "bundleDependencies",
                        "overrides", "resolutions"):
            deps = manifest.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name, _spec in _iter_dep_specs(deps):
                bare = dep_name.split(">")[-1]
                targets = [bare]
                if bare.startswith("@") and "/" in bare:
                    targets.append(bare.split("/", 1)[1])
                for target in targets:
                    if _typosquat_check_name("npm", target, rel,
                                             lines, add):
                        return
        return
    if stem.startswith("requirements") and suffix == ".txt":
        for line in lines:
            clean = line.split("#", 1)[0].strip()
            if not clean or clean.startswith("-"):
                egg = _EGG_RE.search(line)
                if egg and _typosquat_check_name(
                        "pypi", egg.group(1), rel, lines, add):
                    return
                continue
            m = _REQ_NAME_RE.match(clean)
            if m and _typosquat_check_name(
                    "pypi", m.group(1), rel, lines, add):
                return
        return
    if stem == "pyproject.toml":
        for line in lines:
            for m in _TOML_DEP_STR_RE.finditer(line):
                if _typosquat_check_name(
                        "pypi", m.group(1), rel, lines, add):
                    return
        return
    if stem == "setup.py":
        m = _SETUP_REQ_RE.search(text)
        bodies = [m.group(1)] if m else []
        if not bodies:
            # install_requires=REQS with REQS = [...] at module
            # level — the most common real-world setup.py layout
            # (rt18). One level of indirection only.
            vm = _SETUP_VAR_RE.search(text)
            if vm:
                am = re.search(
                    r"^" + re.escape(vm.group(1))
                    + r"\s*(?::[^=\n]*)?=\s*\[(.*?)\]",
                    text, re.DOTALL | re.MULTILINE)
                if am:
                    bodies = [am.group(1)]
        for body in bodies:
            for nm in _SETUP_NAME_RE.finditer(body):
                if _typosquat_check_name(
                        "pypi", nm.group(1), rel, lines, add):
                    return
        return
    if stem == "Pipfile":
        in_packages = False
        for line in lines:
            if line.strip().startswith("["):
                in_packages = bool(_PIPFILE_SECTION_RE.match(line))
                continue
            if in_packages:
                km = _PIPFILE_KEY_RE.match(line)
                if km and _typosquat_check_name(
                        "pypi", km.group(1), rel, lines, add):
                    return
        return


# --------------------------------------------------------------------------
# JS download-and-run: fetch + dynamic code loading in the same file
# --------------------------------------------------------------------------

_JS_FETCH_SHAPE_RE = re.compile(
    r"((?:node:)?https?\s*\.\s*(?:get|request)\s*\(|\bfetch\s*\(|"
    r"\baxios\s*[.(]|\bgot\s*\(|\bundici\b|XMLHttpRequest)")
_JS_LOAD_SHAPE_RE = re.compile(
    r"(?<![\w.])require\s*\(\s*(?![\"'][^\"']{0,500}[\"']\s*[,)])|"
    r"(?<![\w.])eval\s*\(")
_JS_REMOTE_IMPORT_RE = re.compile(
    r"(?<![\w.])import\s*\(\s*[\"']https?://")
_JS_WRITE_FILE_RE = re.compile(
    r"(?:writeFile(?:Sync)?|createWriteStream)\s*\(\s*[\"']([^\"']+)[\"']")
_JS_LITERAL_REQUIRE_RE = re.compile(
    r"(?<![\w.])require\s*\(\s*[\"']([^\"']+)[\"']\s*\)")


def _download_and_run_findings(rel: str, text: str, lines: list[str],
                               add) -> None:
    """The JS analogue of DECODE_AND_RUN: a file that fetches remote
    content AND dynamically loads code (require of a computed path,
    eval) can end up executing whatever the server sends. Either half
    alone is an ordinary capability and is reported by its own rule
    (NETWORK_ACCESS / DYNAMIC_IMPORT / EVAL_EXEC). Callers pass
    comment-blanked text, so a fetch word in a comment is not fetch
    evidence (audit F5)."""
    def fire(pos: int) -> None:
        line_no = text[:pos].count("\n") + 1
        add("DOWNLOAD_AND_RUN", rel, line_no,
            lines[line_no - 1] if 0 < line_no <= len(lines) else "")

    # A dynamic import of a remote URL needs no second half: the
    # import itself fetches and executes (red-team j1).
    m = _JS_REMOTE_IMPORT_RE.search(text)
    if m:
        fire(m.start())
        return
    if not _JS_FETCH_SHAPE_RE.search(text):
        return
    m = _JS_LOAD_SHAPE_RE.search(text)
    if m:
        fire(m.start())
        return
    # Two-stage dropper with a LITERAL require: fetch -> write the
    # response to a file -> require that same file (red-team j2).
    # A literal require alone is ordinary; it is the written-file
    # match that makes it a load of downloaded content.
    written = {p[2:] if p.startswith("./") else p
               for p in _JS_WRITE_FILE_RE.findall(text)}
    if written:
        for m in _JS_LITERAL_REQUIRE_RE.finditer(text):
            req = m.group(1)
            if (req[2:] if req.startswith("./") else req) in written:
                fire(m.start())
                return


# --------------------------------------------------------------------------
# Install-command classification (RUNTIME_PACKAGE_INSTALL refinement)
# --------------------------------------------------------------------------
#
# The benchmark's benign side showed the old line rule's noise shape:
# documentation that tells the user to install a NAMED package from
# the official registry (or the declared requirements file) is
# ordinary setup prose. The dangerous shape is an install whose
# SOURCE is off-registry — a URL, git source, archive file, local
# path, or custom index. Lines are classified by their argument
# segment only (cut at shell / markup boundaries, so a download link
# elsewhere in a table row does not leak into the command).

_INSTALL_CMD_RE = re.compile(
    r"(pip3?\s+install|npm\s+(?:install|i|add)|pnpm\s+(?:add|install)|"
    r"bun\s+(?:add|install)|yarn\s+add|apt(?:-get)?\s+install|"
    r"brew\s+install|gem\s+install)")
_SEGMENT_CUT_RE = re.compile(r"[`]|\]\(")
_CMD_SPLIT_RE = re.compile(r"&&|\|\||;|\|")


def _classify_install_args(seg: str) -> str:
    """Classify one install command's argument tail: "url" /
    "registry" / "bare" (see _install_line_class)."""
    seg = _SEGMENT_CUT_RE.split(seg, maxsplit=1)[0]
    # A trailing shell comment is prose about the command, not an
    # argument (audit F8). '#' only opens a comment after whitespace,
    # so URL fragments (pkg.git#egg=) survive.
    seg = re.split(r"\s+#", seg, maxsplit=1)[0]
    tokens = [t.strip().strip("\"'").strip(",") for t in seg.split()]
    tokens = [t for t in tokens if t]
    # Flag values are judged by flag semantics FIRST (and consumed, so
    # an official index URL is not re-read as a package source by the
    # generic scan below).
    consumed: set[int] = set()
    for i, t in enumerate(tokens):
        base = t.split("=", 1)[0].lower()
        attached = None
        if base in ("-i", "--index-url", "--extra-index-url"):
            flag = "index"
        elif base in ("-e", "--editable"):
            flag = "editable"
        elif re.match(r"^-i\S", t):
            flag, attached = "index", t[2:]
        elif re.match(r"^-e\S", t) and not t.startswith("--"):
            flag, attached = "editable", t[2:]
        else:
            continue
        if attached is not None:
            val = attached
            consumed.add(i)
        elif "=" in t:
            val = t.split("=", 1)[1]
        elif i + 1 < len(tokens):
            val = tokens[i + 1]
            consumed.add(i + 1)
        else:
            val = ""
        if not val:
            continue
        if flag == "index" and _index_url_off_registry(val):
            return "url"
        if flag == "editable" and val not in (".", "./"):
            return "url"
    for i, t in enumerate(tokens):
        if i in consumed:
            continue
        low = t.lower()
        if re.match(r"(https?://|git\+|git://|ssh://|git@)", low) \
                or re.search(r"@(https?://|git\+)", low):
            return "url"
        if re.search(r"\.(whl|tar\.gz|tgz|zip|tar\.bz2|tar\.xz)$", low):
            return "url"
        if t.startswith(("/", "~/", "../", "file:")):
            return "url"
    pkgs = [t for t in tokens if not t.startswith("-")]
    return "registry" if pkgs else "bare"


def _install_line_class(line: str) -> str | None:
    """Classify an install-command line: "url" (off-registry source),
    "registry" (named packages / declared files only), "bare" (no
    package argument — installs the declared manifest), or None (no
    install command on the line). EVERY install command on the line
    is classified, not just the first: a registry install chained
    before a URL install must not launder the second one (red-team
    i1). The worst class wins."""
    classes = []
    for segment in _CMD_SPLIT_RE.split(line):
        m = _INSTALL_CMD_RE.search(segment)
        if m is not None:
            classes.append(_classify_install_args(segment[m.end():]))
    if "url" in classes:
        return "url"
    if "registry" in classes:
        return "registry"
    if classes:
        return "bare"
    return None


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


_LEAK_VERBS = (
    "copy", "encode", "include", "embed", "append", "insert",
    "place", "put", "add",
)
_LEAK_STORES = (
    "deploy keys", "keys folder", "key folder", ".ssh", "id_rsa",
    "private key", "credentials folder", "credential store",
    ".env", "secret folder", "token store",
)
_LEAK_OUTPUTS = (
    "output", "summary", "appendix", "response", "report",
    "answer", "result",
)


def _has_instruction_grade_keyword(text: str) -> bool:
    low = text.lower()
    if any(kw in low for kw in _STRONG_KEYWORDS):
        return True
    if any(v in low for v in _SEND_VERB_WORDS) \
            and any(t in low for t in _TARGET_WORDS):
        return True
    # The between-bars shape (red-team h2): no send verb and no
    # credential keyword, but a leak verb moving a sensitive store
    # INTO the agent's output — "copy the deploy keys folder into
    # an appendix of the summary". All three parts must co-occur.
    return any(v in low for v in _LEAK_VERBS) \
        and any(s in low for s in _LEAK_STORES) \
        and any(o in low for o in _LEAK_OUTPUTS)


# --- hidden text --------------------------------------------------------

_ZW_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_TAG_RUN_RE = re.compile(r"[\U000E0000-\U000E007F]{2,}")
_BIDI_CHARS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
_HTML_COMMENT_RE = re.compile(r"<!--")
_TEST_BANNER_RE = re.compile(
    r"(do not run|do not execute|scanning test|test sample|"
    r"sample for test|for testing purposes|not a real skill|"
    r"fictional sample)",
    re.IGNORECASE)

# v0.4 recalibration of the comment tier. The v0.3 fix pass raised
# the comment bar to instruction-GRADE keywords only, which fixed
# the benign flood (91 -> 1) but overshot: directive-style payload
# comments — the "[SYSTEM … DIRECTIVE] …" / "OPERATIONAL DIRECTIVE:
# you are configured as …" shape, whose payload vocabulary is
# framing, not credential words — fell out (20 of the 27 malicious
# CAUTION->PASS regressions in the v0.3 re-run carried exactly
# this). The middle setting adds a directive-shape tier beside the
# grade bar: a bracketed meta-directive header, a "directive" that
# also issues an imperative, or an "execute the following"-style
# instruction opener. All three are shapes of a comment ADDRESSED
# TO THE AGENT AS ORDERS, which is what makes hidden text a
# finding; ordinary notes, TODOs and harness banners meet none.
_DIRECTIVE_HEADER_RE = re.compile(
    r"\[[^\]\n]{0,100}\b(?:system|directive|trigger|payload|prompt|"
    r"override|admin|reprogramming|operational)\b[^\]\n]{0,80}\]",
    re.IGNORECASE)
_DIRECTIVE_STRONG_BRACKET_WORDS = (
    "system", "override", "trigger", "payload", "reprogramming",
    "admin", "operational",
)
_DIRECTIVE_CO_WORDS = (
    "execute", "you are", "shall", "must", "act as", "configured",
    "follow", "disclose", "reveal", "unrestricted",
)
# Persona-override shapes are directives whatever their framing:
# they re-cast WHO the agent is for the session.
_PERSONA_PHRASES = (
    "stay in character", "remain in character",
    "the assistant persona", "persona for this skill",
    "adopt the persona", "act as if no policy",
)
_AGENT_ADDRESSED_RE = re.compile(
    r"\byou\s+(?:are|must|shall|should|will)\b|\byour\b",
    re.IGNORECASE)
_IMPERATIVE_OPENER_RE = re.compile(
    r"^(?:\[[^\]]*\]\s*)?(?:\w+\s+){0,3}?"
    r"(?:disclose|reveal|execute|ignore|comply|send|upload|leak|"
    r"exfiltrate)\b", re.IGNORECASE)
# A directive that is the TOPIC of human documentation (a framework
# tutorial, a legal instrument summary) is not an order to the
# agent: "a Vue directive", "documenting a custom directive", a
# bracketed framework name.
_DIRECTIVE_TOPIC_RE = re.compile(
    r"(?:\b(?:angular|vue|react|svelte|ember|css)\s+directive\b|"
    r"\b(?:a|the|this|custom|new)\s+(?:\w+\s+)?directive\b|"
    r"\b(?:documenting|describing|explaining|writing|using)\s+"
    r"(?:a\s+)?(?:\w+\s+)?directive\b)",
    re.IGNORECASE)


def _comment_directive_shape(body: str) -> bool:
    """Directive-shape tier for HTML comments, recalibrated by the
    v0.4 review in both directions. Evasion side (red-team h3): the
    bracketed header no longer has to sit at the comment's start,
    and persona-override shapes count. False-positive side (FP
    hunter): a directive ADDRESSED TO HUMANS — a legal instrument,
    a spec, a framework tutorial where the directive is the topic —
    is not an order to the agent, so the tier requires an
    agent-address marker (you/your, an imperative opener, a persona
    shape) unless the bracket itself carries a system word."""
    low = body.lower()
    if any(p in low for p in _PERSONA_PHRASES):
        return True
    if "execute the following" in low or "follow these" in low:
        return True
    topic = bool(_DIRECTIVE_TOPIC_RE.search(body))
    addressed = bool(_AGENT_ADDRESSED_RE.search(body)) \
        or bool(_IMPERATIVE_OPENER_RE.match(body.strip()))
    header = _DIRECTIVE_HEADER_RE.search(body[:400])
    if header and not topic:
        bracket = header.group(0).lower()
        if any(w in bracket for w in _DIRECTIVE_STRONG_BRACKET_WORDS):
            return True
        if addressed:
            return True
    if "directive" in low and not topic:
        if addressed and any(w in low for w in _DIRECTIVE_CO_WORDS):
            return True
    return False


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
    instruction-grade keyword content AND no directive shape. A
    banner phrase riding on the same comment as a payload does NOT
    exempt the payload — the comment is then checked normally (and
    fires at CAUTION like any other keyword-carrying comment). The
    directive-shape clause matters: directive payloads speak in
    framing vocabulary, not credential words, so the grade check
    alone let a banner-worn directive through (red-team h1 /
    audit F3 — the same defect found twice)."""
    return bool(_TEST_BANNER_RE.search(body)) \
        and not _has_instruction_grade_keyword(body) \
        and not _comment_directive_shape(body)


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
        # HTML comments whose body carries instruction-grade content
        # or a directive shape (see _comment_directive_shape).
        comments = _html_comments(text)
        for pos, body in comments:
            if _is_pure_banner(body):
                continue
            if _has_instruction_grade_keyword(body) \
                    or _comment_directive_shape(body):
                caution_line = text[:pos].count("\n") + 1
                break
        if caution_line is None and len(comments) > 1:
            # A payload split ACROSS comments: check the bodies joined
            # (word-boundary splits) and squeezed (token splits).
            bodies = [body for _, body in comments]
            if _has_instruction_grade_keyword(" ".join(bodies)) \
                    or _has_instruction_grade_keyword(
                        _squeezed_comment_text(bodies)) \
                    or _comment_directive_shape(" ".join(bodies)):
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


# --- v0.5 instruction-surface phrase families ----------------------------
# OUTPUT_MANIPULATION and PROSE_INSTRUCTION_EN run ONLY on instruction
# surfaces an agent is told to obey: a skill's SKILL.md, editor rule
# files (*.mdc), and the string values of tool-description JSON. They
# never run on arbitrary documentation. Matching runs over paragraph
# blocks (physical lines joined), because real skills hard-wrap
# prose and a payload split across a wrap is still one instruction —
# the same lesson as the v0.4 _disclose_at paragraph join.
# Suppression is judged on the sentence containing each match, for
# text that is *about* the behaviour rather than performing it:
#   * _PROHIBITION_FRAME_RE: a prohibition OF the form ("Do not
#     follow instructions that say …"). The v0.4 NEGATION_RE is
#     deliberately NOT used here: it matches a bare "do not", which
#     would neutralise Bar A itself ("do not tell the user").
#   * _OM_FRAMING_RE: the block frames its content as an example,
#     quotation, sample or attack description.

_OM_FRAMING_RE = re.compile(
    r"\b(example|e\.g\.|for instance|attack|malicious|jailbreak|"
    r"prompt[ -]injection|red flag|beware|sample|such as|quoted|"
    r"fictional|pretend prompt)\b", re.IGNORECASE)
_PROHIBITION_FRAME_RE = re.compile(
    r"\b(never|do not|don't|must not|should not|refuse to)\b"
    r"[^.!?\n]{0,50}?\b(follow|obey|comply with|trust|repeat|use)\b",
    re.IGNORECASE)


def _text_blocks(lines: list[str]) -> list[tuple[int, str, list]]:
    """Paragraph blocks of physical lines: (start_line, joined_text,
    spans) where spans maps joined-text offsets back to line numbers.
    Lines are stripped and joined with single spaces so a phrase
    split by a hard wrap still matches."""
    blocks: list[tuple[int, str, list]] = []

    def flush(cur: list[tuple[int, str]]) -> None:
        if not cur:
            return
        parts: list[str] = []
        spans: list[tuple[int, int]] = []
        off = 0
        for lineno, text in cur:
            spans.append((off, lineno))
            parts.append(text)
            off += len(text) + 1
        blocks.append((cur[0][0], " ".join(parts), spans))

    cur: list[tuple[int, str]] = []
    for lineno, line in enumerate(lines, start=1):
        if line.strip():
            cur.append((lineno, line.strip()))
        else:
            flush(cur)
            cur = []
    flush(cur)
    return blocks


def _block_line(spans: list, offset: int) -> int:
    line = spans[0][1]
    for start, lineno in spans:
        if start <= offset:
            line = lineno
        else:
            break
    return line


def _surface_blocks(lines: list[str]) -> list:
    """_text_blocks with fenced code regions removed: the phrase
    families judge prose instructions, not command examples (a
    fenced `curl -X POST` is API documentation; command shapes in
    fences are the line rules' and chain rules' business)."""
    fence_lines = [i for i, line in enumerate(lines)
                   if line.lstrip().startswith("```")]
    # An ODD number of fence lines means the last fence never
    # closes; treating it as a fence would silently swallow the
    # remainder of the file (audit F10) — treat the unpaired fence
    # line as ordinary text instead.
    unpaired = fence_lines[-1] if len(fence_lines) % 2 else -1
    kept: list[str] = []
    in_fence = False
    for i, line in enumerate(lines):
        if i != unpaired and line.lstrip().startswith("```"):
            in_fence = not in_fence
            kept.append("")
            continue
        kept.append("" if in_fence else line)
    return _text_blocks(kept)

# Bar A — concealment from the user (design §3.3).
_OM_A_RES = [
    re.compile(r"(?:do not|don't|never)\s+(?:tell|inform|notify)\s+"
               r"the\s+user\b", re.IGNORECASE),
    re.compile(r"never\s+mention\b[^.!?\n]{0,60}?\bto\s+the\s+user\b",
               re.IGNORECASE),
    re.compile(r"never\s+mention\s+(?:this|that|it|the)\b",
               re.IGNORECASE),
    re.compile(r"\bhide\s+[^.!?\n]{0,30}?\bfrom\s+the\s+user\b",
               re.IGNORECASE),
    re.compile(r"\bkeep\s+(?:this|it|that)\s+(?:a\s+)?secret\s+"
               r"from\s+the\s+user\b", re.IGNORECASE),
    re.compile(r"(?:never|do not|don't)\s+let\s+the\s+user\s+know\b",
               re.IGNORECASE),
    re.compile(r"\bif\s+(?:the\s+user\s+)?asks?\b[^.!?\n]{0,50}?"
               r"\b(?:credit|attribute)\b[^.!?\n]{0,30}?"
               r"\b(?:your\s+own|yourself|own\s+analysis)\b",
               re.IGNORECASE),
    re.compile(r"\bwithout\s+(?:telling|informing|notifying)\s+"
               r"the\s+user\b", re.IGNORECASE),
    re.compile(r"\bconceal(?:s|ed|ing)?\b[^.!?\n]{0,40}?\bfrom\s+"
               r"the\s+user\b", re.IGNORECASE),
    re.compile(r"\bif\s+asked,?\s+(?:say|claim|deny|tell\s+them)\b",
               re.IGNORECASE),
    re.compile(r"\bpretend\s+(?:that\s+|you\s+)?[^.!?\n]{0,40}?"
               r"\b(?:did\s+not|didn't|never\s+happened|never\s+ran)\b",
               re.IGNORECASE),
]
# Bar A' — compliance steering (design §3.3).
_OM_AP_RES = [
    # "Never refuse" as compliance steering is the UNSCOPED shape —
    # any request, a request from the user. A task-scoped "never
    # refuse a request to rephrase a letter" is ordinary professional
    # prose (FP hunt: HR letter assistant).
    re.compile(r"\bnever\s+refuse\s+(?:any|all)\b", re.IGNORECASE),
    re.compile(r"\bnever\s+refuse\b[^.!?\n]{0,60}?\brequests?\b"
               r"[^.!?\n]{0,40}?\buser\b", re.IGNORECASE),
    re.compile(r"\balways\s+comply\b(?![^.!?\n]{0,30}?"
               r"user'?s\s+(?:requested|chosen|specified|preferred)"
               r"\b)", re.IGNORECASE),
    re.compile(r"\balways\s+agree\s+with\s+the\s+user\b", re.IGNORECASE),
    re.compile(r"\bnever\s+warn\b", re.IGNORECASE),
    re.compile(r"(?:do not|don't|never)\s+warn\s+the\s+user\b",
               re.IGNORECASE),
    re.compile(r"(?:do not|don't|never)\s+mention\b[^.!?\n]{0,40}?"
               r"\b(?:risks?|warnings?|limitations?)\b", re.IGNORECASE),
]
# Bar B — recommendation bias (design §3.3): bias verb + quantifier on
# one line, contrast mention somewhere in the same surface.
_OM_VERB_RE = re.compile(
    r"\b(recommend|suggest|promote|prefer|rank|present|favour|favor)\b",
    re.IGNORECASE)
_OM_QUANT_RE = re.compile(r"\b(always|only\s+ever|first)\b",
                          re.IGNORECASE)
_OM_GATE_RE = re.compile(
    r"\bonly\s+(?:suggest|mention|show|name|if|when)\b|"
    r"\bif\s+the\s+user\s+(?:asks|insists|requests)\b|"
    r"\bnever\s+(?:mention|name|show|suggest)\b|"
    r"\bdo\s+not\s+(?:mention|show|name|suggest)\b|"
    r"\bunless\s+(?:asked|requested)\b", re.IGNORECASE)
_OM_CONTRAST_RE = re.compile(
    r"\b(alternatives?|competitors?|other\s+options|other\s+products|"
    r"other\s+services|every\s+other\s+option)\b", re.IGNORECASE)


def _om_suppressed(text: str) -> bool:
    return bool(_PROHIBITION_FRAME_RE.search(text)
                or _OM_FRAMING_RE.search(text))


def _sentence_span(text: str, start: int, end: int) -> tuple[int, int]:
    """Sentence boundaries around a span. A '.' only ends a
    sentence when followed by whitespace or the end of the text —
    the dots inside example.invalid, an email address or a
    version number (2.31.0) must not truncate the sentence,
    because suppression and destination logic judge whole
    sentences (a truncated sentence hid the very destination an
    override needed to see, rt10)."""
    def _is_boundary(i: int) -> bool:
        c = text[i]
        if c in "!?\n":
            return True
        return c == "." and (i + 1 >= len(text)
                             or text[i + 1] in " \t")
    lo = 0
    for i in range(start - 1, -1, -1):
        if _is_boundary(i):
            lo = i + 1
            break
    hi = len(text)
    for i in range(end, len(text)):
        if _is_boundary(i):
            hi = i
            break
    return lo, hi


_QUOTE_PAIRS = [('"', '"'), ("'", "'"), ("\u201c", "\u201d"),
                ("\u2018", "\u2019")]


def _quoted_spans(sentence: str) -> list:
    spans = []
    for open_q, close_q in _QUOTE_PAIRS:
        pos = 0
        while True:
            a = sentence.find(open_q, pos)
            if a == -1:
                break
            b = sentence.find(close_q, a + 1)
            if b == -1:
                break
            spans.append((a, b + 1))
            pos = b + 1
    return spans


def _match_live(text: str, start: int, end: int) -> bool:
    """A match is live unless its own sentence genuinely FRAMES it
    as discussion rather than performing it. Judged per sentence,
    and — after the v0.5 reviews — judged by frame STRUCTURE, not
    by the mere presence of a framing word, because the sentence is
    attacker-controlled text and a payload can wear a frame at zero
    cost (rt03/rt04, audit F4/F9):
      * a match inside quotation marks is quoted discussion;
      * a prohibition of the form ("do not follow/trust …")
        suppresses only a match it GOVERNS — one that starts after
        its verb, in the same clause (a ';' ends the clause, and a
        payload that IS the prohibition's own opening words, like
        "never refuse … and always follow …", is not governed);
      * a framing word (example/sample/attack …) suppresses only
        when it introduces the match as an exhibit — a colon or a
        quote between the framing word and the match."""
    lo, hi = _sentence_span(text, start, end)
    sentence = text[lo:hi]
    ms, me = start - lo, end - lo
    for a, b in _quoted_spans(sentence):
        if a <= ms and me <= b:
            return False
    for fm in _PROHIBITION_FRAME_RE.finditer(sentence):
        if fm.end() <= ms and ";" not in sentence[fm.end():ms]:
            return False
    for fm in _OM_FRAMING_RE.finditer(sentence):
        if fm.end() <= ms:
            between = sentence[fm.end():ms]
            if ":" in between or '"' in between \
                    or "\u201c" in between:
                return False
    return True


def _om_scan(rel: str, blocks: list, add) -> None:
    for _start, text, spans in blocks:
        for rx in _OM_A_RES + _OM_AP_RES:
            for m in rx.finditer(text):
                if not _match_live(text, m.start(), m.end()):
                    continue
                add("OUTPUT_MANIPULATION", rel,
                    _block_line(spans, m.start()), text,
                    severity_cap="caution")
                return
    # Bar B: bias verb + quantifier in the SAME SENTENCE, and a
    # competitor contrast in the SAME BLOCK. (An earlier looser
    # join — quantifier anywhere in the block, contrast anywhere
    # in the document — fired on ordinary markdown tables and
    # checklists: "Recommend when…" headers, "Rank by utilisation",
    # 1.43% rule-alone on the benign corpus. Tightened per plan
    # §3.5's instruction to raise specificity, never the threshold.)
    for _start, text, spans in blocks:
        if not _OM_CONTRAST_RE.search(text):
            continue
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            m = _OM_VERB_RE.search(sentence)
            if not m:
                continue
            if not (_OM_QUANT_RE.search(sentence) or re.search(
                    r"\bnever\b", sentence[: m.start()],
                    re.IGNORECASE)):
                continue
            if not re.search(r"\b(always|only\s+ever)\b", sentence,
                             re.IGNORECASE) \
                    and not _OM_GATE_RE.search(text):
                # "Rank X first, and present the alternatives
                # openly below" is a presentation order, not bias:
                # bare "first" counts only when the block also
                # gates or suppresses the alternatives.
                continue
            off = text.find(sentence) + m.start()
            if not _match_live(text, off, off + 1):
                continue
            add("OUTPUT_MANIPULATION", rel,
                _block_line(spans, off), text,
                severity_cap="caution")
            return


def _output_manipulation_findings(rel: str, lines: list[str],
                                  add) -> None:
    _om_scan(rel, _surface_blocks(lines), add)


def _output_manipulation_values(rel: str, values: list[str],
                                add) -> None:
    _om_scan(rel, [(i + 1, v, [(0, i + 1)])
                   for i, v in enumerate(values)], add)


# PROSE_INSTRUCTION_EN (design §6, item d5): English system-prompt
# manipulation shapes on the same instruction surfaces.
_PIE_TARGET_WORD = r"(?:system\s+prompt|instructions|directions|guidance)"
_PIE_RES = [
    re.compile(r"\bignore\s+(?:all\s+|your\s+|the\s+)?"
               r"(?:previous\s+|prior\s+|earlier\s+)?"
               r"(?:instructions|directions)\b", re.IGNORECASE),
    re.compile(r"\bignore\s+your\s+" + _PIE_TARGET_WORD + r"\b",
               re.IGNORECASE),
    re.compile(r"\bdisregard\s+(?:your\s+|the\s+|all\s+)?"
               r"(?:(?:previous|prior|earlier)\s+)?"
               + _PIE_TARGET_WORD + r"\b", re.IGNORECASE),
    re.compile(r"\bforget\s+your\s+" + _PIE_TARGET_WORD + r"\b",
               re.IGNORECASE),
    re.compile(r"\breveal\s+your\s+system\s+prompt\b", re.IGNORECASE),
    re.compile(r"\b(?:print|show|repeat|output|display)\s+"
               r"(?:your\s+|the\s+)?system\s+prompt\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+in\s+developer\s+mode\b",
               re.IGNORECASE),
]
_PIE_SEND_VERB_RE = re.compile(
    r"\b(send|sends|sending|upload|uploads|uploading|mail|mails|"
    r"forward|forwards|forwarding|deliver|delivers|post|posts|"
    r"posting|relay|relays|relaying)\b", re.IGNORECASE)
_PIE_TARGET_RE = re.compile(
    r"\b(contents?|conversation|history|transcript|environment|"
    r"credentials?|documents?|notes?)\b", re.IGNORECASE)
_PIE_DEST_RE = re.compile(
    r"https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+|\bexternal\b",
    re.IGNORECASE)


def _pie_scan(rel: str, blocks: list, add,
              claimed: frozenset = frozenset()) -> None:
    for _start, text, spans in blocks:
        for rx in _PIE_RES:
            for m in rx.finditer(text):
                if not _match_live(text, m.start(), m.end()):
                    continue
                add("PROSE_INSTRUCTION_EN", rel,
                    _block_line(spans, m.start()), text,
                    severity_cap="caution")
                return
        # Send shape: verb + target + external destination must
        # share ONE sentence (a negated mention of "credentials"
        # two sentences later is not a send instruction), and the
        # consent / self / own / local suppressors are judged on
        # THAT sentence — a frame in a neighbouring sentence must
        # not launder this one (audit F5).
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            vm = _PIE_SEND_VERB_RE.search(sentence)
            if (vm and _PIE_TARGET_RE.search(sentence)
                    and _PIE_DEST_RE.search(sentence)
                    and not _disclose_suppressed(sentence)):
                line_no = _block_line(spans, text.find(sentence))
                if line_no in claimed:
                    # PROSE_READ_SEND already reported this exact
                    # sentence; a second finding for the same words
                    # is duplication, not coverage (FP hunt).
                    return
                add("PROSE_INSTRUCTION_EN", rel,
                    line_no, text,
                    severity_cap="caution")
                return


def _prose_instruction_en_findings(rel: str, lines: list[str],
                                   add,
                                   claimed: frozenset = frozenset()
                                   ) -> None:
    _pie_scan(rel, _surface_blocks(lines), add, claimed)


def _prose_instruction_en_values(rel: str, values: list[str],
                                 add) -> None:
    _pie_scan(rel, [(i + 1, v, [(0, i + 1)])
                    for i, v in enumerate(values)], add)


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
    r"(?:\$\(\s*(?:shell\s+)?|`)([^)`]{0,2000})", re.IGNORECASE)
_SUBST_FETCH_RE = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
_PROCESS_SUBST_RE = re.compile(r"<\(\s*(?:curl|wget)\b", re.IGNORECASE)
_EXECUTING_CMD_RE = re.compile(
    r"\b(eval|exec|source|xargs)\b|\b(?:ba|da|z|k)?sh\s+-c\b"
    r"|\bbash\s+-c\b|\bsh\s+-\w*c\b"
    r"|\b(?:python3?|perl|node|ruby|php)\s+-[ce]\b"
    r"|(?:^|[\s;|&])\.\s", re.IGNORECASE)
_BENIGN_CONSUMER_RE = re.compile(
    r"^\s*(?:echo|printf|cat|test|\[|if\b|while\b|until\b|case\b|"
    r"return\b|export\b|local\b|declare\b|readonly\b)", re.IGNORECASE)
_ASSIGN_PREFIX_RE = re.compile(
    r"^\s*(?:export\s+|local\s+|declare\s+|readonly\s+)?"
    r"[A-Za-z_][\w]*\s*[:?+]?=")


def _squeeze_shell_line(line: str) -> str:
    """Normalise shell quoting tricks before matching: collapse
    backslash escapes (c\\url -> curl — in shell a backslash before
    an ordinary character is that character), drop empty quote
    pairs (cu''rl -> curl) and remove quote characters between
    adjacent quoted fragments ('cu'"rl" -> curl)."""
    out = re.sub(r"\\(.)", r"\1", line)
    prev = None
    while prev != out:
        prev = out
        out = out.replace("''", "").replace('""', "")
        out = re.sub(r"(['\"])\1+", r"\1", out)
        out = re.sub(r"(['\"])(?=[A-Za-z])", "", out)
        out = re.sub(r"(?<=[A-Za-z])(['\"])", "", out)
    return out


def _substitution_exec_findings(rel: str, lines: list[str], add,
                                doc: bool = False,
                                comment_spans=None,
                                string_spans=None) -> None:
    """Classify every download-through-substitution site in the file.
    A substitution in an EXECUTING context (command position, eval /
    sh -c / source, piped to a shell, process substitution) is BLOCK:
    the fetched content runs. A substitution that only CAPTURES the
    download (VAR=$(curl …) whose value is never executed by this
    file, a Makefile $(shell …) assignment) is the same shape at
    CAUTION: worth a human look, not proof of execution. Shell files
    arrive variable-expanded, so a captured variable that IS later
    executed shows up here as an executing line in its own right.
    v0.4 precision fix (BENCHMARK_V03 §6.1): in a DOCUMENTATION file
    the executing form is capped at CAUTION like every other rule's
    doc findings — a code-fence example tells the reader to run it,
    it does not run itself. v0.3 BLOCKed 15 benign prose examples
    this way, breaking the zero-false-BLOCK property.
    Inert regions (FP fixtures 36/37/38/48): a substitution inside
    a COMMENT in a code file is prose about the pattern — the site
    is dropped, not merely capped; a substitution inside a STRING
    literal in a Python/JS file is data (those languages have no
    shell substitution), capped at CAUTION. Per-site, not per-file:
    a file that both quotes the pattern AND executes it still
    BLOCKs on the executed site."""
    comment_spans = comment_spans or {}
    string_spans = string_spans or {}

    def inert_kind(lineno: int, col: int) -> str | None:
        for lo, hi in comment_spans.get(lineno, ()):
            if lo <= col < hi:
                return "comment"
        for lo, hi in string_spans.get(lineno, ()):
            if lo <= col < hi:
                return "string"
        return None

    sites: list[tuple[int, bool, str]] = []  # (lineno, executing, line)
    for lineno, raw in enumerate(lines, start=1):
        line = _squeeze_shell_line(raw)[:MAX_LINE_CHARS]
        pm = _PROCESS_SUBST_RE.search(line)
        if pm:
            kind = inert_kind(lineno, pm.start())
            if kind == "comment":
                continue
            sites.append((lineno, kind != "string", raw))
            continue
        for m in _SUBST_INNER_RE.finditer(line):
            inner = m.group(1)
            if not _SUBST_FETCH_RE.search(inner):
                continue
            kind = inert_kind(lineno, m.start())
            if kind == "comment":
                continue  # quoted in a comment: prose, not a site
            if kind == "string":
                sites.append((lineno, False, raw))
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
            sub_at = min(p for p in (line.find("$("), line.find("`"))
                         if p != -1)
            if inert_kind(lineno, sub_at) == "comment":
                continue  # a commented-out capture captures nothing
            name_m = re.search(r"([A-Za-z_][\w]*)\s*[:?+]?=", line)
            if name_m:
                captured[name_m.group(1)] = lineno
    if captured and sites:
        executed: set[int] = set()
        for lineno, raw in enumerate(lines, start=1):
            line = _squeeze_shell_line(raw)
            spans = comment_spans.get(lineno)
            if spans:
                # Execution evidence inside a comment executes
                # nothing; only the live part of the line counts.
                line = line[:spans[0][0]]
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
        add("SUBSTITUTION_EXEC", rel, lineno, raw,
            severity_cap="caution" if doc else None)
    else:
        lineno, _, raw = sites[0]
        add("SUBSTITUTION_EXEC", rel, lineno, raw,
            severity_cap="caution")


# --- prose chains & the agent-as-channel combination (v0.4) -----------------

_ARCHIVE_TARGET_RE = re.compile(
    r"https?://\S{1,300}?\.(?:zip|tar|tar\.gz|tgz|dmg|pkg|msi|exe|bin|run|"
    r"jar|deb|rpm|appimage|sh|bash)\b"
    r"|[\w./-]{1,120}?\.(?:zip|tar\.gz|tgz|dmg|pkg|msi|exe|bin|run|jar|deb|"
    r"rpm|appimage|sh|bash)\b",
    re.IGNORECASE)

# _ARCHIVE_TARGET_RE's path alternative rescans up to 120 characters
# at every position — near-quadratic on a multi-MB dot-less file
# (the audit-F1 disease again). The search used by the chain checks
# therefore anchors on the extension dot (rare) and walks back over
# a bounded path prefix: linear in the text, O(120) per candidate.
_ARCHIVE_EXT_RE = re.compile(
    r"\.(?:zip|tar(?:\.gz)?|tgz|dmg|pkg|msi|exe|bin|run|jar|deb|rpm|"
    r"appimage|sh|bash)\b", re.IGNORECASE)
_PATH_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_./-~")


class _TargetHit:
    """Minimal match stand-in returned by _archive_target()."""

    __slots__ = ("_start", "_text")

    def __init__(self, start: int, text: str) -> None:
        self._start = start
        self._text = text

    def start(self) -> int:
        return self._start

    def group(self, _n: int = 0) -> str:
        return self._text


def _archive_target(text: str) -> _TargetHit | None:
    for m in _ARCHIVE_EXT_RE.finditer(text):
        i = m.start()
        if i == 0 or text[i - 1] in "/.":
            continue  # a bare ".zip" mention is not a file target
        j = i
        while j > 0 and i - j < 120 and text[j - 1] in _PATH_CHARS:
            j -= 1
        return _TargetHit(j, text[j:m.end()])
    return None
_URL_TARGET_RE = re.compile(r"https?://\S{1,300}")
_CHAIN_DOWNLOAD_RE = re.compile(
    r"\b(?:download|fetch|retrieve|grab)(?:s|ed|ing)?\b|"
    r"\bget(?:s|ting)?\b|\bcurl\b|\bwget\b",
    re.IGNORECASE)
# The execution step must plausibly apply to the DOWNLOADED OBJECT:
# run/install/open IT, or a named executable thing (the installer,
# the tool, a .sh/.exe file), or an interpreter invocation of a
# script file. "Launch the game", "open scores.csv in your
# spreadsheet app" and "restart your design application" are steps
# in honest setup docs whose object is not the download (FP hunter
# fixtures 11/12/13) and meet none of these shapes.
_CHAIN_EXECUTE_RE = re.compile(
    r"chmod\s+\+x"
    r"|\./[\w.-]+"
    r"|\b(?:run|execute|launch|start|open)\s+(?:it\b|the\s+(?:installer|"
    r"setup|tool|binary|program|app|application|script|archive|executable)\b|"
    r"[\w.-]+\.(?:sh|bash|exe|bin|run|msi|pkg|dmg|appimage|jar|py|js|mjs)\b)"
    r"|\b(?:run|execute)\s+(?:the\s+)?(?:downloaded|extracted|unzipped)\b"
    r"|\b(?:bash|sh|zsh|python3?|node|perl|ruby)\s+[\w./-]+\."
    r"(?:sh|bash|py|js|mjs|pl|rb)\b"
    r"|\binstall\s+(?:it\b|the\s+(?:installer|setup|binary|tool)\b|"
    r"[\w.-]+\.(?:sh|exe|msi|pkg|deb|rpm|dmg)\b)",
    re.IGNORECASE)


_CHAIN_STAGE_RE = re.compile(
    r"\b(?:extract|unzip|unpack|decompress)(?:s|ed|ing)?\b|"
    r"\b(?:keep|save|store)\s+(?:it|the\s+(?:file|script|tool|"
    r"download|archive)\b)|chmod\s+\+x",
    re.IGNORECASE)


def _prose_chain_parts(text: str):
    """(target_match, needs_stage, has_download, has_execute,
    has_stage) for one document's text — the chain ingredients, so
    the per-document and the folder-level joins share one
    definition. A bare-URL target (no archive / binary / installer
    filename) additionally needs a STAGING step (extract, keep it,
    save it, chmod): "download the helper, keep it, then run it"
    is a staged dropper chain, while "download the app and run it"
    is how every app page on the internet reads (the v0.4 suite's
    FP control), so the bare URL alone is not a target."""
    target = _archive_target(text)
    needs_stage = False
    if target is None:
        target = _URL_TARGET_RE.search(text)
        needs_stage = target is not None
    return (target, needs_stage,
            bool(_CHAIN_DOWNLOAD_RE.search(text)),
            bool(_CHAIN_EXECUTE_RE.search(text)),
            bool(_CHAIN_STAGE_RE.search(text)))


_CHAIN_NEGATION_RE = re.compile(
    r"\b(never|do not|don't|must not|should not|refuse[sd]?|"
    r"avoid|forbidden|prohibited)\b", re.IGNORECASE)


def _prose_chain_negated(text: str, pos: int) -> bool:
    """A warning that NAMES the chain to forbid it ("never download
    installer.zip from random sites and run it") is safety prose,
    not a chain (audit F4). The negation must GOVERN the chain:
    a strong prohibition in the same clause, before the target.
    A bare "not" elsewhere on the line ("This step is not
    optional: download the tool … and run it") negates something
    else and laundered live chains (audit F6)."""
    lo, _hi = _sentence_span(text, pos, pos)
    clause = max(text.rfind(":", lo, pos), text.rfind(";", lo, pos))
    prefix = text[max(lo, clause + 1):pos]
    return bool(_CHAIN_NEGATION_RE.search(prefix))


def _prose_download_run_findings(rel: str, text: str, add) -> None:
    """Document-level join for the by-hand dropper chain (coverage
    S3): an external archive/binary target + a download step + a
    run/execute step, anywhere in one document. Single lines rarely
    carry the whole chain in prose skills — the steps are a numbered
    list — so the join is per-document. Package-manager installs of
    named software do not meet the target test (an archive, binary
    or installer-script file, or a bare URL, must be the object)."""
    target, needs_stage, has_download, has_execute, \
        has_stage = _prose_chain_parts(text)
    if not target or not has_download or not has_execute:
        return
    if needs_stage and not has_stage:
        return
    if _prose_chain_negated(text, target.start()):
        return
    line_no = text[:target.start()].count("\n") + 1
    add("PROSE_DOWNLOAD_RUN", rel, line_no,
        target.group(0)[:160], severity_cap="caution")


# --- v0.5 prose chain extensions ------------------------------------------
# Shared paragraph/step blocks: chains written as numbered steps or
# bullet lists live in one blank-line-separated block.

def _paragraph_blocks(text: str) -> list[tuple[int, int, str]]:
    """(start_line, start_offset, block_text) per blank-line block."""
    blocks: list[tuple[int, int, str]] = []
    current: list[str] = []
    start_line = 1
    start_off = 0
    off = 0
    for idx, line in enumerate(text.split("\n"), start=1):
        if line.strip():
            if not current:
                start_line, start_off = idx, off
            current.append(line)
        else:
            if current:
                blocks.append((start_line, start_off, "\n".join(current)))
                current = []
        off += len(line) + 1
    if current:
        blocks.append((start_line, start_off, "\n".join(current)))
    return blocks


# (d1) fetch-a-script-and-run-it, including anaphoric execute steps.
_SCRIPT_URL_RE = re.compile(
    r"https?://\S+?\.(?:sh|bash|py|ps1|rb|pl|bat|cmd)\b", re.IGNORECASE)
_ANAPHOR_EXEC_RE = re.compile(
    r"\brun\s+(?:it|that|the\s+(?:script|file|tool|program|installer|"
    r"converter|helper))\b|\bexecute\s+(?:it|the\s+(?:script|file|"
    r"tool|program))\b|\blaunch\s+(?:it|the\s+(?:script|file|tool|"
    r"program))\b", re.IGNORECASE)


def _prose_fetch_execute_findings(rel: str, text: str, add) -> None:
    if not _CHAIN_DOWNLOAD_RE.search(text):
        return
    blocks = _paragraph_blocks(text)
    for idx, (start_line, start_off, block) in enumerate(blocks):
        m = _SCRIPT_URL_RE.search(block)
        if m and (_CHAIN_EXECUTE_RE.search(block)
                  or _ANAPHOR_EXEC_RE.search(block)):
            if _prose_chain_negated(text, start_off + m.start()):
                continue
            line_no = start_line + block[: m.start()].count("\n")
            add("PROSE_FETCH_EXECUTE", rel, line_no,
                m.group(0)[:160], severity_cap="caution")
            return
        um = _URL_TARGET_RE.search(block)
        if not (um and _CHAIN_DOWNLOAD_RE.search(block)):
            continue
        # Anaphoric execute in this block or the following one,
        # WITH a staging step (save/store/keep it, extract, chmod):
        # "download the app and run it" — no staging — is the
        # ordinary app-install sentence and a v0.4 control case;
        # fetch → stage to disk → run-the-staged-thing is the
        # dropper shape this variant exists for.
        following = blocks[idx + 1][2] if idx + 1 < len(blocks) else ""
        staged = (_CHAIN_STAGE_RE.search(block)
                  or _CHAIN_STAGE_RE.search(following)
                  or "somewhere" in block.lower())
        if staged and (_ANAPHOR_EXEC_RE.search(block)
                       or _ANAPHOR_EXEC_RE.search(following)):
            if _prose_chain_negated(text, start_off + um.start()):
                continue
            line_no = start_line + block[: um.start()].count("\n")
            add("PROSE_FETCH_EXECUTE", rel, line_no,
                um.group(0)[:160], severity_cap="caution")
            return
    # Document-level join (rt01): a script URL in one block, a
    # filler paragraph, and "run the script" two blocks later is
    # still one instruction — the block join alone let a single
    # intervening paragraph defeat it.
    m = _SCRIPT_URL_RE.search(text)
    if m and (_CHAIN_EXECUTE_RE.search(text)
              or _ANAPHOR_EXEC_RE.search(text)):
        if _prose_chain_negated(text, m.start()):
            return
        line_no = text[: m.start()].count("\n") + 1
        add("PROSE_FETCH_EXECUTE", rel, line_no,
            m.group(0)[:160], severity_cap="caution")


# (d2) pipe-a-download-into-a-shell instructions.
_FETCH_TOKEN_RE = re.compile(
    r"\b(?:curl|wget)\b|Invoke-WebRequest|\birm\b", re.IGNORECASE)
_PIPE_SHELL_RE = re.compile(
    r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b|\biex\b", re.IGNORECASE)
_PIPE_PROSE_RE = re.compile(
    r"\bpipes?\b[^.!?\n]{0,40}\b(?:sh|bash|shell|powershell)\b",
    re.IGNORECASE)
_PIPE_HAND_RE = re.compile(
    r"\b(?:hand|give|feed|pass)\b[^.!?\n]{0,50}?\b(?:to|into)\s+"
    r"(?:bash|sh|zsh|a\s+shell|the\s+shell)\b", re.IGNORECASE)


def _prose_pipe_instruction_findings(rel: str, text: str, add) -> None:
    lines = text.split("\n")
    in_fence = False
    fence: list[str] = []
    fence_start = 0
    for idx, line in enumerate(lines, start=1):
        if line.lstrip().startswith("```"):
            if in_fence:
                block = "\n".join(fence)
                if _FETCH_TOKEN_RE.search(block) and (
                        _PIPE_SHELL_RE.search(block)
                        or ("chmod" in block and "./" in block)):
                    add("PROSE_PIPE_INSTRUCTION", rel, fence_start,
                        fence[0][:160] if fence else "",
                        severity_cap="caution")
                    return
                fence = []
                in_fence = False
            else:
                in_fence = True
                fence_start = idx
                fence = []
            continue
        if in_fence:
            fence.append(line)
    for start_line, _off, block in _paragraph_blocks(text):
        if _FETCH_TOKEN_RE.search(block) and (
                _PIPE_PROSE_RE.search(block)
                or _PIPE_HAND_RE.search(block)):
            add("PROSE_PIPE_INSTRUCTION", rel, start_line,
                block.split("\n")[0][:160], severity_cap="caution")
            return


# (d4) safety-bypass instructions. The LURE_WITH_BYPASS combination
# (this + a download-and-run chain anywhere in the folder) is formed
# in scan_folder.
_BYPASS_RES = [
    re.compile(r"\bdisable\b[^.!?\n]{0,40}?\b(?:antivirus|smart ?screen|"
               r"gatekeeper|defender|firewall|virus\s+protection)\b",
               re.IGNORECASE),
    re.compile(r"\bturn\s+off\b[^.!?\n]{0,40}?\b(?:antivirus|"
               r"smart ?screen|gatekeeper|defender|firewall|"
               r"virus\s+protection)\b", re.IGNORECASE),
    re.compile(r"\bswitch\s+off\b[^.!?\n]{0,40}?\b(?:antivirus|"
               r"smart ?screen|gatekeeper|defender|firewall|"
               r"virus\s+protection)\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(?:the\s+|any\s+)?(?:security|certificate|"
               r"safety)\s+warnings?\b", re.IGNORECASE),
    re.compile(r"\badd\s+(?:an?\s+)?(?:exception|exclusion)\b[^.!?\n]"
               r"{0,40}?\b(?:antivirus|defender|firewall)\b",
               re.IGNORECASE),
    re.compile(r"\bbypass\s+(?:the\s+)?(?:security|antivirus|"
               r"smart ?screen|gatekeeper)\b", re.IGNORECASE),
]
_RUN_ADMIN_RE = re.compile(
    r"\brun\s+(?:it\s+|the\s+\w+\s+)?as\s+administrator\b|"
    r"\brun\s+(?:it\s+)?with\s+sudo\b", re.IGNORECASE)
_INSTALLISH_RE = re.compile(
    r"\b(?:download|install|run|execute|launch|fetch)\b", re.IGNORECASE)


# Paragraphs that DISCUSS protection-disabling rather than
# instruct it: anti-phishing training ("Scammers may call … They
# will tell you to disable your antivirus. Never do this"),
# false-positive remedy docs, and temporary-with-restore
# troubleshooting ("temporarily disable … turn it back on
# afterwards"). Judged on the match's whole paragraph (FP hunt).
_BYPASS_FRAME_RE = re.compile(
    r"\b(?:scam|scammers|phishing|fraud|pretending\s+to\s+be|"
    r"never\s+do\s+this|do\s+not\s+do\s+this|"
    r"false\s+positives?|turn\s+it\s+back\s+on|"
    r"re-?enable\b[^.!?\n]{0,40}?\bafter)\b", re.IGNORECASE)
# Right-click → Open is Apple's own documented flow for opening an
# unsigned app; "bypass the Gatekeeper warning, right-click the
# app and choose Open" instructs that flow, not a disabling.
_SANCTIONED_OPEN_RE = re.compile(
    r"\bright[\s-]?click(?:ing|s|ed)?\b[^.!?\n]{0,60}?"
    r"\bchoos(?:e|ing)\s+open\b|"
    r"\bright[\s-]?click(?:ing|s|ed)?\b[^.!?\n]{0,40}?\bopen\b",
    re.IGNORECASE)


def _prose_safety_bypass_findings(rel: str, text: str, add) -> None:
    has_context = bool(re.search(r"https?://", text)
                       or _INSTALLISH_RE.search(text))
    if not has_context:
        return
    # Paragraph blocks: a bypass instruction split by a hard wrap
    # ("… — disable" / "SmartScreen and your antivirus …") is one
    # instruction. Discussion-framed sentences are exempt.
    singles = _text_blocks(text.split("\n"))
    # A blank line between the verb and its target (rt12) defeats
    # the per-block join; adjacent-block pairs are tried too.
    pairs = []
    for i in range(len(singles) - 1):
        _s1, t1, sp1 = singles[i]
        _s2, t2, sp2 = singles[i + 1]
        off = len(t1) + 1
        pairs.append((_s1, t1 + " " + t2,
                      sp1 + [(off + o, ln) for o, ln in sp2]))
    for _start, joined, spans in singles + pairs:
        if _BYPASS_FRAME_RE.search(joined):
            continue
        for rx in _BYPASS_RES:
            for m in rx.finditer(joined):
                if not _match_live(joined, m.start(), m.end()):
                    continue
                sentence = _sentence_around(joined, m.start(),
                                            m.end())
                if _SANCTIONED_OPEN_RE.search(sentence):
                    continue
                add("PROSE_SAFETY_BYPASS", rel,
                    _block_line(spans, m.start()), joined,
                    severity_cap="caution")
                return
    for m in _RUN_ADMIN_RE.finditer(text):
        window = text[max(0, m.start() - 200): m.start() + 200]
        if _INSTALLISH_RE.search(window):
            line_no = text[: m.start()].count("\n") + 1
            add("PROSE_SAFETY_BYPASS", rel, line_no,
                text.split("\n")[line_no - 1][:160],
                severity_cap="caution")
            return


# The agent-as-channel shape: code that READS local files + prose
# that directs DISCLOSURE to an external destination. Neither half
# fires alone — a file reader is a utility, and send instructions
# without a reader have nothing to carry — but together the agent
# becomes the exfiltration channel, outside the code entirely.
_CODE_READ_RE = re.compile(
    r"\bopen\s*\(|\.read\s*\(|read_text|read_bytes|"
    r"readFile(?:Sync)?\s*\(|createReadStream|"
    r"read_csv\s*\(|(?<![\w.])cat\s+[^\s|;&]+")
_DISCLOSE_VERB_RE = re.compile(
    r"\b(?:send|upload|share|email|forward|transmit|post|deliver|"
    r"publish|relay)(?:ing|ed|es|s|d)?\b", re.IGNORECASE)
_DISCLOSE_DEST_RE = re.compile(
    r"https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+|\bserver\b|\bendpoint\b|"
    r"\bwebhook\b|\bexternal\b|"
    r"\b(?:telegram|discord|slack|whatsapp|signal)\b", re.IGNORECASE)
_DISCLOSE_CONTENT_RE = re.compile(
    r"\b(?:contents of the|file contents|contents of ~/|"
    r"upload the file|send the file)\b", re.IGNORECASE)
# Disclosure shapes that are NOT the agent-as-channel pattern,
# judged on the verb's own sentence: an explicit negation ("never
# send …"), a user-consent gate ("when the user clicks Share …"),
# a self recipient ("email me the summary"), a destination the
# user configured or owns ("the endpoint configured by the user"),
# or a local destination ("on the local server"). Each is a
# mechanically recognisable frame in honest skills (FP fixtures
# 15–22); none of them appears in the stealer shape, where the
# destination is the author's and sending is unconditional.
_DISCLOSE_SUPPRESS_RES = [
    re.compile(
        r"user\s+(?:clicks|chooses|approves|confirms|requests|"
        r"initiates|selects)\b|clicks?\s+(?:approve|share|publish)\b|"
        r"after\s+the\s+user\b|when\s+the\s+user\b|"
        r"user'?s\s+(?:approval|consent|permission|request)\b|"
        r"with\s+(?:the\s+)?user'?s?\s+(?:consent|approval|"
        r"permission)\b|asks?\s+the\s+user\b", re.IGNORECASE),
    re.compile(
        r"email\s+me\b|send\s+(?:it|this|that|them)\s+to\s+me\b|"
        r"to\s+the\s+user\s+themsel|only\s+to\s+you\b|yourself\b",
        re.IGNORECASE),
    re.compile(
        r"configured\s+(?:by|in|via)\b|user[- ]configured|"
        r"your\s+own\b|user'?s\s+own\b|"
        r"\bown\s+(?:endpoint|server|account|bucket|storage)\b",
        re.IGNORECASE),
    re.compile(
        r"local\s+(?:server|host|machine|endpoint|network)\b|"
        r"localhost\b|127\.0\.0\.1|on\s+this\s+machine|"
        r"stays\s+on\s+this\s+machine", re.IGNORECASE),
    re.compile(
        r"\buser\s+(?:downloaded|provided|picked|selected|"
        r"uploaded|shared|supplied|gave)\b|"
        r"\bthe\s+user\s+picks\b", re.IGNORECASE),
    re.compile(
        r"\b(?:tell|inform|notify|show)\s+the\s+user\b"
        r"[^.!?\n]{0,80}?\bbefore\s+(?:sending|send|uploading|"
        r"posting)\b", re.IGNORECASE),
]

_CONCRETE_DEST_RE = re.compile(
    r"https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+", re.IGNORECASE)
_LOCAL_DEST_RE = re.compile(
    r"localhost|127\.0\.0\.1|\[::1\]", re.IGNORECASE)


def _disclose_suppressed(sentence: str, following: str = "") -> bool:
    """Whether a consent / self / own / local frame genuinely covers
    THIS sentence's send (rt09/rt10, audit F5). The frames assert
    something about the destination — the user's own endpoint,
    the user themself — so they hold only when the sentence names
    no concrete destination they fail to describe: an author-
    asserted "user's own endpoint" in front of a generic webhook
    URL, or "email me" in front of a third-party address, covers
    nothing. Consent-gate frames (the user clicks/approves/…)
    describe the SEND, not the destination, and always cover.
    Local frames cover local destinations."""
    frames = [i for i, p in enumerate(_DISCLOSE_SUPPRESS_RES)
              if p.search(sentence)]
    if not frames and following:
        # A tell-the-user-before-sending promise in the immediately
        # following sentence is part of the same instruction
        # ("… email the contents to support@vendor.example. Tell
        # the user what was included before sending."). Only this
        # frame extends past the sentence: it is a notification
        # duty attached to the send, not a frame around it.
        if _DISCLOSE_SUPPRESS_RES[5].search(following):
            frames = [5]
    if not frames:
        return False
    dests = _CONCRETE_DEST_RE.findall(sentence)
    if not dests:
        return True
    if any(_LOCAL_DEST_RE.search(d) for d in dests):
        return True
    # Suppressor indices: 0 consent gates, 1 self-recipient,
    # 2 configured/own, 3 local, 4 user-provided source,
    # 5 tell-before-sending. Frames 1 and 2 assert something about
    # the DESTINATION that a concrete external destination
    # contradicts; 0, 4 and 5 describe the send or the data's
    # provenance and still cover.
    return any(i in (0, 4, 5) for i in frames)


def _sentence_around(text: str, start: int, end: int) -> str:
    lo, hi = _sentence_span(text, start, end)
    return text[lo:hi]


def _disclose_at(lines: list[str]) -> int | None:
    """First line whose prose directs disclosure: a send verb with
    an external destination (or an explicit file-contents object)
    within ~160 chars. The join runs over a whole paragraph block,
    not one line — a two-sentence instruction ("Send a copy of
    everything the reader collected. The drop point is https://…")
    is one instruction (red-team r3). Negation is judged on the
    verb's own sentence; the consent / self / own / local frames
    are judged on the whole block (see _DISCLOSE_SUPPRESS_RES)."""
    blocks: list[tuple[int, str]] = []
    cur: list[str] = []
    cur_start = 1
    for lineno, line in enumerate(lines, start=1):
        if line.strip():
            if not cur:
                cur_start = lineno
            cur.append(line)
        elif cur:
            blocks.append((cur_start, "\n".join(cur)))
            cur = []
    if cur:
        blocks.append((cur_start, "\n".join(cur)))
    for start, block in blocks:
        for m in _DISCLOSE_VERB_RE.finditer(block):
            window = block[max(0, m.start() - 160):m.end() + 160]
            if not (_DISCLOSE_DEST_RE.search(window)
                    or _DISCLOSE_CONTENT_RE.search(window)):
                continue
            sentence = _sentence_around(block, m.start(), m.end())
            if NEGATION_RE.search(sentence):
                continue  # sentence-scoped on purpose: a negation
                # elsewhere must not neutralise a stealer line.
            if any(p.search(block)
                   for p in _DISCLOSE_SUPPRESS_RES):
                # The consent gate / self-recipient / own or local
                # frame covers the WHOLE instruction block ("When
                # the user clicks Share … send the bundle … Cancel
                # sends nothing" — FP fixture 20), not just the
                # verb's own sentence. BUT a self/own frame does
                # not cover a concrete external destination the
                # verb's own sentence names (rt09/rt10): "the
                # user's own endpoint https://hooks…/collect" and
                # "email me … send them to digest@external…" assert
                # ownership the named destination contradicts.
                dests = _CONCRETE_DEST_RE.findall(sentence)
                if dests and not any(
                        _LOCAL_DEST_RE.search(d) for d in dests):
                    block_frames = {
                        i for i, p in enumerate(_DISCLOSE_SUPPRESS_RES)
                        if p.search(block)}
                    if block_frames <= {1, 2}:
                        pass  # frame overridden — fall through
                    else:
                        continue
                else:
                    continue
            return start + block[:m.start()].count("\n")
    return None


# (d3) prose read-and-send: the read half in prose, the disclosure
# half a send verb + STRICT destination (URL, email address, or an
# "external" marker) in one sentence, with the shared consent /
# self / own / local suppressors. No code read is required — the
# agent is the channel for both halves. The destination test is
# stricter than READ_AND_DISCLOSE's _disclose_at on purpose: with
# no code-read pairing to constrain it, the bare word "server"
# fired on ordinary API documentation (benign-corpus measurement),
# and third-party subjects ("user sends photos…", "clients send
# requests…") describe other people's traffic, not an instruction
# to the agent.
_PROSE_READ_RE = re.compile(
    r"\b(?:read|open|collect|gather|load|index|scan)\b[^.!?\n]{0,80}?"
    r"\b(?:files?|folder|directory|documents|contents|notes|records|"
    r"text)\b", re.IGNORECASE)
_THIRD_PARTY_SEND_RE = re.compile(
    r"\b(?:user|users|client|clients|customer|customers|visitor|"
    r"visitors|they|he|she)\s+(?:sends?|uploads?|forwards?|posts?|"
    r"shares?|emails?)\b", re.IGNORECASE)


def _prose_read_send_findings(rel: str, lines: list[str], add):
    """Returns the physical lines this rule claimed (for the
    same-sentence dedupe against PROSE_INSTRUCTION_EN's send
    shape), or an empty list."""
    text = "\n".join(lines)
    if not _PROSE_READ_RE.search(text):
        return []
    blocks = _paragraph_blocks(text)
    doc_has_dest = bool(_PIE_DEST_RE.search(text)
                        or _DISCLOSE_CONTENT_RE.search(text))

    def fire(joined: str, block_lines: list, start: int,
             m) -> list:
        acc = 0
        line_no = start
        for bl in block_lines:
            if acc + len(bl) >= m.start():
                break
            acc += len(bl) + 1
            line_no += 1
        add("PROSE_READ_SEND", rel, line_no,
            lines[line_no - 1] if 0 < line_no <= len(lines) else "",
            severity_cap="caution")
        return [line_no]

    for start, _off, block in blocks:
        block_lines = block.split("\n")
        joined = " ".join(block_lines)
        for m in _DISCLOSE_VERB_RE.finditer(joined):
            window = joined[max(0, m.start() - 160): m.end() + 160]
            if not (_PIE_DEST_RE.search(window)
                    or _DISCLOSE_CONTENT_RE.search(window)):
                continue
            sentence = _sentence_around(joined, m.start(), m.end())
            if NEGATION_RE.search(sentence):
                continue
            if _THIRD_PARTY_SEND_RE.search(sentence):
                continue
            _lo, _hi = _sentence_span(joined, m.start(), m.end())
            if _disclose_suppressed(sentence, joined[_hi:_hi + 200]):
                continue  # judged on the verb's own sentence: a
                # consent/self/own frame in a neighbouring sentence
                # must not launder this send (audit F5)
            return fire(joined, block_lines, start, m)
    if not doc_has_dest:
        return []
    # Document-level join (rt08): the destination may live in its
    # own block — the natural "contact details at the end" layout —
    # far beyond any per-block window. The read half is already
    # established for the whole document; a live send verb anywhere
    # in it completes the shape — but the verb's own sentence must
    # carry a content object (contents / transcript / documents /
    # …): with a document-wide destination, a bare send verb near
    # nothing in a link-heavy document is documentation noise
    # (fix-pass benign measurement: this join alone took the
    # rule's benign rule-alone rate from 0.85% to 2.86% before
    # the content-object requirement).
    for start, _off, block in blocks:
        block_lines = block.split("\n")
        joined = " ".join(block_lines)
        for m in _DISCLOSE_VERB_RE.finditer(joined):
            sentence = _sentence_around(joined, m.start(), m.end())
            if not _PIE_TARGET_RE.search(sentence):
                continue
            if NEGATION_RE.search(sentence):
                continue
            if _THIRD_PARTY_SEND_RE.search(sentence):
                continue
            _lo, _hi = _sentence_span(joined, m.start(), m.end())
            if _disclose_suppressed(sentence, joined[_hi:_hi + 200]):
                continue
            return fire(joined, block_lines, start, m)
    return []


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
    # DEPENDENCY_EXECUTION is scoped per package (audit F2): an
    # off-registry source and an install-time execution path combine
    # only when they live in the SAME directory — one package's
    # lifecycle script must not escalate another package's source.
    dep_scopes: dict[str, tuple[str, int]] = {}
    exec_scopes: dict[str, tuple[str, int]] = {}
    read_at: tuple[str, int] | None = None
    disclose_at: tuple[str, int] | None = None
    prose_docs: list[tuple[str, str]] = []
    # v0.5 LURE_WITH_BYPASS combination inputs: first hit per
    # (rule, file) — the combination now also judges PROXIMITY.
    chain_pos: dict[str, int] = {}
    bypass_pos: dict[str, int] = {}
    # Lines PROSE_READ_SEND claimed, per file (PIE dedupe).
    claimed_send: dict[str, set[int]] = {}

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
        if rule_id in ("PROSE_DOWNLOAD_RUN", "PROSE_FETCH_EXECUTE"):
            chain_pos.setdefault(rel, line)
        if rule_id == "PROSE_SAFETY_BYPASS":
            bypass_pos.setdefault(rel, line)
        scope = rel.rpartition("/")[0]
        if rule_id == "DEPENDENCY_SOURCE":
            dep_scopes.setdefault(scope, (rel, line))
        if rule_id in ("PACKAGE_INSTALL_SCRIPT",
                       "PACKAGE_INSTALL_SCRIPT_EXEC",
                       "ENV_INJECTION_INSTALL",
                       "MCP_UNRESTRICTED_EXEC"):
            # A routine lifecycle command (tsc build, patch-package,
            # git-describe versioning) is an install hook's presence,
            # not install-time execution — it does not arm the
            # combination (audit F2).
            if rule_id != "PACKAGE_INSTALL_SCRIPT" \
                    or not _install_evidence_routine(evidence):
                exec_scopes.setdefault(scope, (rel, line))

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
            parsed = None
            parse_failed_deep = False
            try:
                parsed = json.loads(text)
            except (RecursionError, MemoryError):
                parse_failed_deep = True
            except ValueError:
                parsed = None  # invalid JSON: raw-text rules stand;
                # manifest analysis reports its own coverage.
            if parse_failed_deep:
                result.skipped.append(Skipped(
                    rel, "JSON value analysis skipped: nesting too "
                         "deep", True))
            elif parsed is not None:
                # Iterative value walk: a recursively-defined walk
                # died silently at depth ~1000 and took the whole
                # parsed-value pass (hidden text, OM, PIE) with it
                # (audit F8).
                def _string_values(root_node):
                    stack = [root_node]
                    while stack:
                        node = stack.pop()
                        if isinstance(node, str):
                            yield node
                        elif isinstance(node, dict):
                            stack.extend(node.values())
                        elif isinstance(node, list):
                            stack.extend(node)

                try:
                    value_lines = list(_string_values(parsed))
                    if value_lines:
                        _hidden_text_findings(
                            rel, "\n".join(value_lines), value_lines,
                            True, add)
                        _non_english_findings(rel, value_lines, add)
                        _any_language_structure_findings(
                            rel, value_lines, add)
                        # v0.5: tool descriptions are instruction
                        # surfaces.
                        _output_manipulation_values(rel, value_lines,
                                                    add)
                        _prose_instruction_en_values(rel, value_lines,
                                                     add)
                except Exception:
                    result.skipped.append(Skipped(
                        rel, "JSON value analysis failed", True))

        # Python AST first: it identifies sends whose destination is a
        # cloud metadata endpoint itself, and the line pass below must
        # not count those as sends (FP2).
        metadata_send_lines: set[int] = set()
        if suffix == ".py":
            try:
                metadata_send_lines = _ast_findings(
                    path, rel, text, add, flags,
                    note=result.skipped.append)
            except Exception:
                # Deeply nested / pathological syntax trees can defeat the
                # AST analyser (e.g. recursion limits). Line rules below
                # still run; record the gap instead of crashing.
                result.skipped.append(Skipped(rel, "python AST analysis failed", True))

        # Line rules (shell files get variable expansion first).
        scan_lines = _expand_shell_lines(lines) if suffix in (".sh", ".bash", ".zsh") else lines
        # Inert regions for this file: comments (all code languages)
        # and string literals (Python/JS) are prose/data, not
        # behaviour. Line rules run on comment-blanked lines;
        # setup.py — a metadata file whose docstrings ARE its
        # documentation — gets string blanking too. The dedicated
        # matchers receive the span maps for per-site decisions.
        comment_spans: dict[int, list[tuple[int, int]]] = {}
        string_spans: dict[int, list[tuple[int, int]]] = {}
        if suffix == ".py":
            _ccols, string_spans = _py_inert_regions(text)
            comment_spans = {
                ln: [(c, len(lines[ln - 1]))]
                for ln, c in _ccols.items() if ln <= len(lines)}
        elif suffix in (".sh", ".bash", ".zsh"):
            for _ln, _lt in enumerate(scan_lines, start=1):
                _c = _shell_comment_col(_lt)
                if _c is not None:
                    comment_spans[_ln] = [(_c, len(_lt))]
        elif suffix in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
            comment_spans, string_spans = _js_inert_regions(lines)
        rule_lines = _blank_spans(scan_lines, comment_spans)
        if path.name == "setup.py" and string_spans:
            rule_lines = _blank_spans(rule_lines, string_spans)
        for lineno, line_text in enumerate(rule_lines, start=1):
            if doc and NEGATION_RE.search(line_text):
                # Documentation that warns AGAINST a pattern ("never reads
                # ~/.ssh") is safety documentation, not behaviour.
                continue
            stripped = line_text.lstrip()
            # Install-command classification: an off-registry install
            # source is its own finding (INSTALL_FROM_URL), and in
            # documentation a named-registry (or bare / requirements)
            # install is ordinary setup prose that RUNTIME_PACKAGE_
            # INSTALL must not flag — the benchmark's benign-noise fix.
            inst_class = None
            if any(w in line_text for w in
                   ("install", "yarn", "npm", "pnpm", "bun", "pip")):
                inst_class = _install_line_class(line_text)
                if inst_class == "url":
                    add("INSTALL_FROM_URL", rel, lineno,
                        lines[lineno - 1] if lineno - 1 < len(lines)
                        else line_text)
            for rule in LINE_RULES:
                if rule.id == "RUNTIME_PACKAGE_INSTALL" \
                        and inst_class is not None:
                    if inst_class == "url":
                        continue  # INSTALL_FROM_URL carries this line
                    if doc and inst_class in ("registry", "bare"):
                        continue  # ordinary setup prose in docs
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
            # Lines that are entirely comments are skipped: comment
            # prose is not behaviour in this pass either.
            blanked_js = _blank_spans(lines, comment_spans)
            comment_only = {
                ln for ln, bl in enumerate(blanked_js, start=1)
                if not bl.strip() and lines[ln - 1].strip()}
            squeezed = [
                re.sub(r"([\"'])\s*\+\s*([\"'])", "", line_text)
                for line_text in lines
            ]
            for lineno, line_text in enumerate(squeezed, start=1):
                if lineno in comment_only:
                    continue
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
            _dependency_findings(rel, path, text, lines, add)
            _typosquat_findings(rel, path, text, lines, add)
            if suffix in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
                # Comment-blanked text: a fetch word in a comment is
                # not fetch evidence (audit F5).
                _download_and_run_findings(
                    rel, "\n".join(_blank_spans(lines, comment_spans)),
                    lines, add)
            _hidden_text_findings(rel, text, lines, doc, add)
            _env_injection_findings(rel, text, scan_lines, add)
            _substitution_exec_findings(rel, scan_lines, add, doc,
                                        comment_spans, string_spans)
            if doc:
                prose_docs.append((rel, text))
                _prose_download_run_findings(rel, text, add)
                _prose_fetch_execute_findings(rel, text, add)
                _prose_pipe_instruction_findings(rel, text, add)
                _prose_safety_bypass_findings(rel, text, add)
                claimed_send[rel] = set(
                    _prose_read_send_findings(rel, lines, add))
                if disclose_at is None:
                    dl = _disclose_at(lines)
                    if dl is not None:
                        disclose_at = (rel, dl)
            if suffix in (".py", ".js", ".ts", ".mjs", ".cjs", ".sh",
                          ".jsx", ".tsx", ".bash", ".zsh") \
                    and read_at is None:
                rm = _CODE_READ_RE.search(text)
                if rm:
                    read_at = (rel,
                               text[:rm.start()].count("\n") + 1)
            if suffix == ".pth":
                _pth_findings(rel, lines, add)
            if doc:
                _markdown_concealment_findings(rel, text, lines, add)
                _any_language_structure_findings(rel, lines, add)
                if path.name.lower() == "skill.md" or suffix == ".mdc":
                    # v0.5 instruction-surface phrase families.
                    _output_manipulation_findings(rel, lines, add)
                    _prose_instruction_en_findings(
                        rel, lines, add,
                        frozenset(claimed_send.get(rel, ())))
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

    # Folder-level prose chain: the download step in one document
    # and the run step in another (README + docs/RUN.md) is one
    # chain split across files (red-team p1). Only when no single
    # document already carried the whole chain.
    if prose_docs and not any(k[0] == "PROSE_DOWNLOAD_RUN"
                              for k in index):
        target_hit = None
        any_download = False
        any_execute = False
        any_stage = False
        for rel_doc, doc_text in prose_docs:
            t, ns, d, e, s = _prose_chain_parts(doc_text)
            if t is not None and target_hit is None:
                target_hit = (rel_doc, doc_text, t, ns)
            any_download = any_download or d
            any_execute = any_execute or e
            any_stage = any_stage or s
        if target_hit is not None and any_download and any_execute \
                and (not target_hit[3] or any_stage):
            rel_doc, doc_text, t = target_hit[0], target_hit[1], \
                target_hit[2]
            if not _prose_chain_negated(doc_text, t.start()):
                line_no = doc_text[:t.start()].count("\n") + 1
                add("PROSE_DOWNLOAD_RUN", rel_doc, line_no,
                    t.group(0)[:160], severity_cap="caution")

    # Folder-level fetch-execute join (rt13): the download in
    # SKILL.md and the run step in docs/RUN.md is one chain split
    # across files — the same join PROSE_DOWNLOAD_RUN already had.
    if prose_docs and not any(k[0] == "PROSE_FETCH_EXECUTE"
                              for k in index):
        fetch_at = None
        any_execute = False
        for rel_doc, doc_text in prose_docs:
            if _SCRIPT_URL_RE.search(doc_text) \
                    and _CHAIN_DOWNLOAD_RE.search(doc_text):
                if fetch_at is None:
                    fetch_at = (rel_doc, doc_text)
            if _CHAIN_EXECUTE_RE.search(doc_text) \
                    or _ANAPHOR_EXEC_RE.search(doc_text):
                any_execute = True
        if fetch_at is not None and any_execute:
            rel_doc, doc_text = fetch_at
            m = _SCRIPT_URL_RE.search(doc_text)
            if m and not _prose_chain_negated(doc_text, m.start()):
                line_no = doc_text[: m.start()].count("\n") + 1
                add("PROSE_FETCH_EXECUTE", rel_doc, line_no,
                    m.group(0)[:160], severity_cap="caution")

    # Off-registry dependency sourcing is a caution alone, but paired
    # with an automatic execution path (install-time hook, loader
    # injection at install, an unrestricted-exec tool declaration) IN
    # THE SAME PACKAGE it is the malicious-package shape: unreviewed
    # code, run for free.
    for scope in dep_scopes.keys() & exec_scopes.keys():
        add("DEPENDENCY_EXECUTION", *dep_scopes[scope])
        break

    # Agent-as-channel: code that reads local files + instructions
    # that direct disclosure to an external destination. Neither
    # half fires alone; together the agent carries the data out.
    if read_at is not None and disclose_at is not None:
        add("READ_AND_DISCLOSE", disclose_at[0], disclose_at[1])

    # v0.5 lure combination: a download-and-run chain + a safety-
    # bypass instruction IN THE SAME FILE, NEAR EACH OTHER. The
    # v0.5 build joined the two halves folder-wide, which BLOCKed
    # ordinary vendor documentation — a printer FAQ in one file
    # and an installer in another, a Defender-exclusion remedy in
    # a troubleshooting doc (FP hunt: 5 benign BLOCKs, all from
    # this join). A lure writes its disarm instruction next to its
    # chain; proximity is part of the shape.
    for rel_f, b_line in bypass_pos.items():
        c_line = chain_pos.get(rel_f)
        if c_line is not None and abs(c_line - b_line) <= 40:
            add("LURE_WITH_BYPASS", rel_f, b_line)
            break

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
