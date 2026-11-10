"""Deterministic rule definitions for SkillScan.

Every rule is plain data: an id, a severity, a plain-English reason and a
compiled regex applied line-by-line to text files. Python files additionally
go through `ast` checks in scanner.py, which map syntax nodes onto the same
rule ids. No rule uses an LLM; a verdict is fully reproducible from the
folder contents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str  # "block" or "caution"
    reason: str
    pattern: re.Pattern


def _rule(rule_id: str, severity: str, reason: str, pattern: str) -> Rule:
    return Rule(rule_id, severity, reason, re.compile(pattern, re.IGNORECASE))


def _metadata_pattern() -> str:
    """Cloud metadata endpoints in every cheap textual form: dotted IP,
    decimal-integer IP (2852039166), hex IP (0xa9fea9fe), the AWS IPv6
    endpoint, the Google hostname, and the well-known paths (including
    the IMDSv2 token path /latest/api/token). The integer/hex forms are
    computed from the dotted constants so they cannot drift apart."""
    parts = [
        r"169\.254\.169\.254", r"169\.254\.170\.2",
        r"metadata\.google\.internal", r"metadata\.goog\b",
        r"/latest/meta-data/", r"/latest/api/token",
        r"/computeMetadata/v1/", r"fd00:ec2::254",
    ]
    for dotted in ("169.254.169.254", "169.254.170.2"):
        value = 0
        for octet in dotted.split("."):
            value = (value << 8) + int(octet)
        parts.append(rf"\b{value}\b")          # decimal form
        parts.append(rf"0x0*{value:x}\b")      # hex form
    return "(" + "|".join(parts) + ")"


METADATA_PATTERN = _metadata_pattern()


RULES: list[Rule] = [
    _rule(
        "SSH_CREDENTIAL_READ", "block",
        "Reads SSH credential material (~/.ssh / private key files). A skill "
        "has no legitimate reason to read your SSH keys.",
        r"(\.ssh\b|id_rsa|id_ed25519|id_ecdsa|id_dsa)",
    ),
    _rule(
        "CLOUD_CREDENTIAL_READ", "block",
        "Reads cloud credential files (~/.aws, ~/.azure, ~/.gcloud), which "
        "can hand over full cloud-account access.",
        r"(\.aws\b|\.azure\b|\.gcloud\b|aws_access_key|aws_secret)",
    ),
    _rule(
        "ENV_FILE_READ", "block",
        "Reads a .env file, where API keys and passwords are commonly stored. "
        "(JS process.env is environment access, not this rule. Placeholder "
        "templates such as .env.example / .env.sample / .env.template are "
        "not flagged — they hold no real values.)",
        r"((?<![\w])\.env\b(?!\.(example|sample|template|dist|defaults)\b)|dotenv|load_dotenv)",
    ),
    _rule(
        "ENVIRON_SECRET_ACCESS", "caution",
        "Accesses environment variables from the host environment, where API "
        "keys and tokens commonly live.",
        r"(os\.environ\b|getenv\s*\(|process\.env\b)",
    ),
    _rule(
        "NETWORK_ACCESS", "caution",
        "Makes network requests. Network access is common in honest skills, "
        "but it is also the channel used to send your data away — check where it talks to.",
        r"((?<![\w.])(requests|urllib|httpx)\s*\.|(?<![\w.])http\.client\b|"
        r"(?<![\w.])socket\s*\.\s*(socket|create_connection)\b|"
        r"(?<![\w.])(fetch|axios|XMLHttpRequest)\s*\(|(?<![\w.])curl\s|(?<![\w.])wget\s)",
    ),
    _rule(
        "NETWORK_SEND_DATA", "block",
        "Sends data out over the network (HTTP POST/PUT, curl -d, a Request "
        "with a body). Combined with any local file access this is the "
        "classic exfiltration shape.",
        r"((?<![\w.])(requests|httpx)\s*\.\s*(post|put|patch)\s*\(|"
        r"\.post\s*\(\s*['\"]https?://|urlopen\s*\([^)]*data\s*=|"
        r"curl[^\n]*\s(-d\b|--data\b|--data-binary\b|--post-data\b)|"
        r"wget[^\n]*--post-data\b)",
    ),
    _rule(
        "SHELL_SUBPROCESS", "caution",
        "Runs external programs via subprocess / child_process. Sometimes "
        "legitimate (backups, media tools); always worth reading before you install.",
        r"((?<![\w.])subprocess\s*\.\s*(?-i:run|Popen|call|check_output|check_call)\s*\(|"
        r"child_process\s*\.|(?<![\w.])execSync\s*\(|(?<![\w.])spawnSync\s*\()",
    ),
    _rule(
        "SHELL_OS_SYSTEM", "block",
        "Runs shell commands through os.system / os.popen, with full shell "
        "interpretation and no argument safety.",
        r"(os\.system\s*\(|os\.popen\s*\(|commands\.getoutput)",
    ),
    _rule(
        "EVAL_EXEC", "block",
        "Evaluates or executes dynamic code strings (eval/exec). Whatever the "
        "string contains runs with the agent's full permissions.",
        r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|__import__\s*\(",
    ),
    _rule(
        "BASE64_OBFUSCATION", "caution",
        "Decodes base64 / encoded blobs. Encoding is sometimes innocent, but "
        "in an installable skill it often hides the real payload from reviewers.",
        r"((?<![\w.])(base64\s*\.\s*\w+|b64decode\s*\(|b64encode\s*\(|atob\s*\(|fromhex\s*\())",
    ),
    _rule(
        "DECODE_AND_RUN", "block",
        "Decodes an encoded payload AND executes dynamic code in the same file "
        "— the standard obfuscated-dropper pattern.",
        r"(b64decode|base64)",  # file-level co-occurrence handled in scanner.py
    ),
    _rule(
        "CURL_PIPE_BASH", "block",
        "Downloads a script and pipes it straight into a shell (curl|bash / "
        "wget|sh). The downloaded code is never reviewed before it runs.",
        r"(curl[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh)|wget[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh))",
    ),
    _rule(
        "FILE_DELETE", "caution",
        "Deletes files (os.remove / os.unlink / shutil.rmtree). Legitimate in "
        "cleanup tools, dangerous everywhere else — check exactly what it deletes.",
        r"(shutil\.rmtree\s*\(|os\.remove\s*\(|os\.unlink\s*\(|pathlib[^\n]*\.unlink\s*\()",
    ),
    _rule(
        "RM_RF", "block",
        "Uses `rm -rf`, recursive forced deletion that can wipe directories "
        "outside the skill's own folder.",
        r"rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r",
    ),
    _rule(
        "PERSISTENCE", "block",
        "Installs persistence outside the skill folder (crontab, shell "
        "startup files, LaunchAgents, systemd units, autostart entries) so "
        "code keeps running after the skill is removed.",
        r"(crontab|\.bashrc|\.zshrc|\.profile\b|LaunchAgents|LaunchDaemons|systemd|\.config/autostart|rc\.local)",
    ),
    _rule(
        "HOME_OR_SYSTEM_WRITE", "caution",
        "Resolves or touches paths in the home directory or system locations "
        "(Path.home, expanduser, $HOME, /etc, /usr/local) instead of staying "
        "inside its own skill folder.",
        r"(Path\.home\s*\(|expanduser\s*\(|getpwuid|homedir\s*\(|\$HOME\b|/etc/|/usr/local/)",
    ),
    _rule(
        "CHMOD_CHOWN", "caution",
        "Changes file permissions or ownership (chmod/chown), which can make "
        "files world-writable or lock the owner out.",
        r"(os\.chmod\s*\(|os\.chown\s*\(|(?<![\w.])chmod\s|(?<![\w.])chown\s)",
    ),
    _rule(
        "RUNTIME_PACKAGE_INSTALL", "caution",
        "Installs packages at run time (pip install / npm install / apt-get "
        "install) instead of declaring dependencies up front — the installed "
        "code is unreviewed and unpinned.",
        r"(pip3?\s+install|npm\s+install|yarn\s+add|apt(-get)?\s+install|brew\s+install|gem\s+install)",
    ),
    _rule(
        "DYNAMIC_IMPORT", "caution",
        "Loads modules or functions dynamically (importlib / getattr) in a "
        "way static review cannot fully resolve. Indirection like this is "
        "how payloads hide from reviewers — read it by hand.",
        r"(importlib\.import_module\s*\()",
    ),
    _rule(
        "CREDENTIAL_ENUMERATION", "caution",
        "Enumerates files with glob/walk patterns that look like credential "
        "discovery (id_*, .ssh*, *key*) instead of naming one file it needs.",
        r"(glob\s*\([^)]*(id_|\.ssh|\*key)|rglob\s*\([^)]*(id_|\.ssh))",
    ),
    _rule(
        "EXFIL_COMBINATION", "block",
        "This skill both reads credential / private material AND has a "
        "way to send data out over the network. That combination is the "
        "exfiltration shape, whatever either half claims to be for.",
        r"(?!)never-matches-line-level",  # scan-level combination, scanner.py
    ),
    _rule(
        "MCP_UNRESTRICTED_EXEC", "block",
        "This MCP manifest declares a tool that runs arbitrary caller-supplied "
        "commands / code with the user's permissions and no constraint.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "MCP_UNRESTRICTED_READ", "caution",
        "This MCP manifest declares a tool that reads arbitrary files by "
        "unconstrained path, so anything on the machine can be pulled in.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "MCP_SERVER_COMMAND", "caution",
        "This MCP manifest starts a server through a shell / interpreter / "
        "package runner command — that command runs on your machine at agent start.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "HARDCODED_SECRET_LIVE", "block",
        "Contains a credential in an unambiguous live format (an AWS "
        "access-key id, a GitHub or GitLab token, an sk- API key, a "
        "Stripe live key, an npm token, a Slack token, or a private-key "
        "block) written directly into the skill. Real keys "
        "do not belong inside installable code — treat this one as "
        "compromised. Placeholder values and clearly-marked documentation "
        "examples are deliberately not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "HARDCODED_SECRET_GENERIC", "caution",
        "Assigns a long, high-entropy literal to a password / secret / "
        "token / api-key variable. It may be an innocent test value, but "
        "hardcoded credentials in shipped code have a way of being real — "
        "check it, and prefer environment variables. Obvious placeholders "
        "and environment-variable references are not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "CLOUD_METADATA_ACCESS", "caution",
        "References a cloud metadata endpoint (169.254.169.254, "
        "169.254.170.2, metadata.google.internal, /latest/meta-data/) "
        "in dotted, decimal-integer, hex, or IPv6 form, or the IMDSv2 "
        "token path. That service hands out temporary cloud credentials "
        "to anything that can reach it, so a skill has almost no "
        "legitimate reason to talk to it — on its own this is a caution; "
        "combined with an outbound send it becomes a block "
        "(CLOUD_METADATA_EXFIL). Sending TO the metadata endpoint itself "
        "(the IMDSv2 token PUT) is this rule, not exfiltration.",
        METADATA_PATTERN,
    ),
    _rule(
        "CLOUD_METADATA_EXFIL", "block",
        "This skill reaches a cloud metadata endpoint (a source of live "
        "cloud credentials) AND reads credential material or has a way "
        "to send data out over the network. That is the cloud "
        "credential-theft shape.",
        r"(?!)never-matches-line-level",  # scan-level combination, scanner.py
    ),
    _rule(
        "BROWSER_CREDENTIAL_STORE", "caution",
        "Touches browser or wallet credential storage (browser profile "
        "password/cookie stores such as Login Data, logins.json, key4.db, "
        "Local State, browser profile directories, or wallet extension "
        "storage). Reading these is what stealer malware does; a skill "
        "that also sends data out is blocked as EXFIL_COMBINATION.",
        r"(Login Data\b|logins\.json|key4\.db|cookies\.sqlite|Local State\b|"
        r"Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|"
        r"wallet\.dat|\.electrum\b|google-chrome\b|BraveSoftware|"
        r"Chrome[/\\]User Data|Edge[/\\]User Data|mozilla[/\\]firefox|"
        r"User Data[/\\](Default|Profile))",
    ),
    _rule(
        "REVERSE_SHELL", "block",
        "Builds a raw-socket reverse shell: it opens a socket connection "
        "and wires it to a shell (socket fd duplication with dup2, "
        "pty.spawn, /dev/tcp, or spawning /bin/sh alongside a socket). "
        "That hands an interactive shell on this machine to whoever is "
        "listening at the other end.",
        r"(?!)never-matches-line-level",  # file-level check in scanner.py
    ),
    _rule(
        "ERROR_INFO_LEAK", "caution",
        "Returns raw exception text, a formatted stack trace, or an "
        "environment dump as a tool result. Whatever calls the tool "
        "(including the model) then sees internal paths, messages and "
        "possibly secrets that were in the environment. Logging the "
        "error and returning a plain message is the safe shape and is "
        "not flagged.",
        r"(return[^\n]*(traceback\.format_exc|format_exc\s*\())",
    ),
    _rule(
        "PACKAGE_INSTALL_SCRIPT", "caution",
        "This package runs code automatically at install time: an npm "
        "lifecycle script (preinstall / install / postinstall / prepare) "
        "or a setup.py that does more than declare metadata (subprocess, "
        "network, sockets). Install-time code runs before you ever call "
        "the tool — read it before installing.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "PACKAGE_INSTALL_SCRIPT_EXEC", "block",
        "An install-time script downloads or executes outside code "
        "(curl/wget download, pipe to a shell, encoded payload, network "
        "fetch from a script). Code fetched at install time is never "
        "reviewed before it runs — this is the classic malicious-package "
        "shape.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "SCAN_INCOMPLETE", "caution",
        "Some content in this folder could not be scanned (unreadable, "
        "oversized, special file, symlink, or nothing was scanned at all). "
        "A verdict based on partial coverage must not be read as clean.",
        r"(?!)never-matches-line-level",  # scanner bookkeeping, scanner.py
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}

# Rules that must NOT be applied as plain line regexes (handled specially).
FILE_LEVEL_RULE_IDS = {
    "DECODE_AND_RUN", "EXFIL_COMBINATION", "MCP_UNRESTRICTED_EXEC",
    "MCP_UNRESTRICTED_READ", "MCP_SERVER_COMMAND", "SCAN_INCOMPLETE",
    "HARDCODED_SECRET_LIVE", "HARDCODED_SECRET_GENERIC",
    "CLOUD_METADATA_EXFIL", "REVERSE_SHELL",
    "PACKAGE_INSTALL_SCRIPT", "PACKAGE_INSTALL_SCRIPT_EXEC",
}
LINE_RULES = [r for r in RULES if r.id not in FILE_LEVEL_RULE_IDS]
