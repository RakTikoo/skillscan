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
import json
import os
import re
import stat
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

DOC_EXTENSIONS = {".md", ".txt", ".rst", ".adoc", ".yaml", ".yml"}
DOC_NAMES = {"LICENSE", "LICENCE", "CHANGELOG", "NOTICE"}
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

CREDENTIAL_RULES = {"SSH_CREDENTIAL_READ", "CLOUD_CREDENTIAL_READ", "ENV_FILE_READ"}
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


def _check_credential_value(value: str, rel: str, line: int, add) -> None:
    if ".ssh" in value or "id_rsa" in value or "id_ed25519" in value \
            or "id_ecdsa" in value or "id_dsa" in value:
        add("SSH_CREDENTIAL_READ", rel, line)
    if ".aws" in value or ".azure" in value or ".gcloud" in value:
        add("CLOUD_CREDENTIAL_READ", rel, line)
    if value.rstrip("/").endswith(".env") or "/.env" in value or value == ".env":
        add("ENV_FILE_READ", rel, line)


def _ast_findings(path: Path, rel: str, text: str, add, flags: dict) -> None:
    try:
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    sym = _Symbols()
    _collect_symbols(tree, sym)

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
                flags["decode"] = (rel, line)

        if dotted in _AST_CALL_RULES:
            add(_AST_CALL_RULES[dotted], rel, line)

        module = dotted.split(".")[0] if dotted else ""
        method = dotted.rsplit(".", 1)[-1] if dotted else ""

        # HTTP client calls (alias-resolved).
        if module in ("requests", "httpx"):
            if method in _SEND_METHODS:
                add("NETWORK_SEND_DATA", rel, line)
                flags["send"] = (rel, line)
            elif method in ("get", "head", "request"):
                kw_names = {kw.arg for kw in node.keywords}
                if "params" in kw_names or "data" in kw_names:
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
                    flags["urllib_send"] = (rel, line)
            if method == "urlopen" and "urllib_send" in flags:
                add("NETWORK_SEND_DATA", rel, line)
                flags["send"] = (rel, line)
        elif dotted.startswith("http.client"):
            add("NETWORK_ACCESS", rel, line)
            if method in ("request", "putrequest"):
                kw_names = {kw.arg for kw in node.keywords}
                if "body" in kw_names or len(node.args) >= 4:
                    add("NETWORK_SEND_DATA", rel, line)
                    flags["send"] = (rel, line)

        # Generic socket / send methods on any receiver.
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("send", "sendall", "sendto"):
            base = _raw_dotted(node.func.value)
            if "sock" in base.lower() or dotted.startswith("socket"):
                add("NETWORK_SEND_DATA", rel, line)
                flags["send"] = (rel, line)
            else:
                add("NETWORK_ACCESS", rel, line)

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
                add("NETWORK_SEND_DATA", rel, line)
                flags["send"] = (rel, line)
            if joined:
                _check_credential_value(joined, rel, line, add)

        # Decode-class calls (for DECODE_AND_RUN class co-occurrence).
        if module in ("base64", "binascii") or method in ("b64decode", "a2b_base64", "fromhex"):
            flags["decode"] = (rel, line)
        if dotted in ("eval", "exec", "__import__") or raw in (
                "importlib.import_module", "import_module") or dotted.startswith("subprocess."):
            flags.setdefault("run_sink", (rel, line))

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

    if "decode" in flags and "run_sink" in flags:
        rel_d, line_d = flags["decode"]
        add("DECODE_AND_RUN", rel_d, line_d)


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


def _manifest_findings(rel: str, text: str, lines: list[str], add) -> None:
    try:
        data = json.loads(text)
    except Exception:
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
# Main scan
# --------------------------------------------------------------------------

def scan_folder(root: Path) -> ScanResult:
    root = root.resolve()
    result = ScanResult(target=str(root))
    index: dict[tuple[str, str], Finding] = {}
    flags: dict = {}
    send_at: tuple[str, int] | None = None
    cred_at: tuple[str, int] | None = None

    def add(rule_id: str, rel: str, line: int, evidence: str = "", severity_cap: str | None = None) -> None:
        nonlocal send_at, cred_at
        rule = RULES_BY_ID[rule_id]
        severity = rule.severity
        if severity_cap == "caution" and severity == "block":
            severity = "caution"
        key = (rule_id, rel)
        existing = index.get(key)
        if existing is not None:
            existing.count += 1
            return
        finding = Finding(rule=rule_id, severity=severity, file=rel, line=line,
                          reason=rule.reason, evidence=evidence.strip()[:160])
        index[key] = finding
        result.findings.append(finding)
        if rule_id in CREDENTIAL_RULES and cred_at is None:
            cred_at = (rel, line)
        if rule_id in SEND_RULES and send_at is None:
            send_at = (rel, line)

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
                _manifest_findings(rel, text, lines, add)
            except Exception:
                result.skipped.append(Skipped(rel, "manifest analysis failed", True))

        # Line rules (shell files get variable expansion first).
        scan_lines = _expand_shell_lines(lines) if suffix in (".sh", ".bash", ".zsh") else lines
        for lineno, line_text in enumerate(scan_lines, start=1):
            if doc and NEGATION_RE.search(line_text):
                # Documentation that warns AGAINST a pattern ("never reads
                # ~/.ssh") is safety documentation, not behaviour.
                continue
            for rule in LINE_RULES:
                if doc and rule.id == "NETWORK_ACCESS":
                    continue  # hyperlinks in prose are not network code
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

        if suffix == ".py":
            try:
                _ast_findings(path, rel, text, add, flags)
            except Exception:
                # Deeply nested / pathological syntax trees can defeat the
                # AST analyser (e.g. recursion limits). Line rules above
                # have already run; record the gap instead of crashing.
                result.skipped.append(Skipped(rel, "python AST analysis failed", True))

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

        if "send" in flags and send_at is None:
            send_at = flags["send"]

    # Scan-level combination: credential access + a send channel anywhere in
    # the same skill is the exfiltration shape.
    if cred_at is not None and (send_at is not None or "send" in flags):
        at = send_at or flags.get("send") or cred_at
        add("EXFIL_COMBINATION", at[0], at[1])

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
