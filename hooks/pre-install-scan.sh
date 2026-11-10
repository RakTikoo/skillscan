#!/usr/bin/env bash
# SkillScan pre-install hook (example).
#
# Scan a skill / MCP server / package folder BEFORE installing it, and
# refuse the install when SkillScan says BLOCK.
#
# Usage:
#   hooks/pre-install-scan.sh <folder-to-scan>
#
# Exit code: whatever SkillScan exits with —
#   0 = PASS    (safe to proceed, as far as static rules can tell)
#   1 = CAUTION (patterns worth a human read; this hook still allows it,
#                but prints the report so the human actually reads it)
#   2 = BLOCK   (known-bad pattern found; do not install)
#   3 = the scan itself could not run (treat as "do not install")
#
# Wire it into an installer wrapper, e.g.:
#   ./hooks/pre-install-scan.sh ./some-skill && cp -r ./some-skill ~/.skills/
#
# The scanner location defaults to the root of this repository (the
# parent of this hooks/ folder). Override with SKILLSCAN_HOME if you
# keep the scanner somewhere else.

set -u

if [ $# -ne 1 ]; then
    echo "usage: $0 <folder-to-scan>" >&2
    exit 3
fi

TARGET="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLSCAN_HOME="${SKILLSCAN_HOME:-$(dirname "$SCRIPT_DIR")}"

if [ ! -d "$TARGET" ]; then
    echo "SkillScan pre-install: '$TARGET' is not a folder — not installing." >&2
    exit 3
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "SkillScan pre-install: python3 was not found on PATH — cannot scan, not installing." >&2
    exit 3
fi

if [ ! -f "$SKILLSCAN_HOME/skillscan.py" ]; then
    echo "SkillScan pre-install: scanner not found at '$SKILLSCAN_HOME/skillscan.py' (set SKILLSCAN_HOME to the SkillScan repo root) — not installing." >&2
    exit 3
fi

echo "SkillScan pre-install: scanning '$TARGET' before install..."
python3 "$SKILLSCAN_HOME/skillscan.py" "$TARGET"
code=$?

case "$code" in
    0) echo "SkillScan pre-install: PASS — no known-bad patterns found." ;;
    1) echo "SkillScan pre-install: CAUTION — read the findings above before installing." ;;
    2) echo "SkillScan pre-install: BLOCK — known-bad pattern found. Do not install." >&2 ;;
    *) echo "SkillScan pre-install: scan could not run (exit $code). Do not install." >&2
       code=3 ;;
esac

exit "$code"
