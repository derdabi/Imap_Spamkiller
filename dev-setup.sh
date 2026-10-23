#!/usr/bin/env bash
# Local development setup for contributors (Linux/macOS).
# Creates a Python virtualenv, installs backend + frontend dependencies.
# This is NOT needed to run the app normally - use Docker/Podman for that.
# Windows users: run start-debug.ps1 instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
VENV="$ROOT/.venv"

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "Required command '$1' was not found in PATH." >&2; exit 1; }
}

require python3
require npm

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi

"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/pip" install -r "$BACKEND/requirements.txt"

if [ ! -d "$FRONTEND/node_modules" ]; then
    npm --prefix "$FRONTEND" install
fi

cat <<EOF

Setup complete.

Run the backend tests:
    cd backend && ../.venv/bin/python -m pytest

Run the backend (dev):
    cd backend && PYTHONPATH=. ../.venv/bin/python -m uvicorn spamkiller.main:app --reload

Run the frontend (dev):
    npm --prefix frontend run dev
EOF
