#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"
rm -f "$DIST"/*.skill "$DIST"/*.zip
(
  cd "$ROOT/skills"
  zip -r "$DIST/healthcheck.skill" healthcheck -x '*/__pycache__/*' '*.pyc' >/dev/null
  zip -r "$DIST/agent-security.skill" agent-security -x '*/__pycache__/*' '*.pyc' >/dev/null
)
echo "Packaged skills into $DIST"
ls -1 "$DIST"
