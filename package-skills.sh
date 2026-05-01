#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"
rm -f "$DIST"/*.skill "$DIST"/*.zip
(
  cd "$ROOT/skills"
  zip -r "$DIST/healthcheck.skill" healthcheck >/dev/null
  zip -r "$DIST/agent-security.skill" agent-security >/dev/null
)
echo "Packaged skills into $DIST"
ls -1 "$DIST"
