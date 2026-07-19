#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CONF="$ROOT/srt-recon.conf"

# Load config
if [ -f "$CONF" ]; then
    # shellcheck source=/dev/null
    source "$CONF"
fi

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    echo "[*] Shutting down..."
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null && wait "$FRONTEND_PID" 2>/dev/null
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null && wait "$BACKEND_PID" 2>/dev/null
    echo "[+] Stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "[+] Starting SRT-Recon..."

# Ensure Go tools are in PATH
GO_TOOLS_PATH="${GO_TOOLS_PATH:-$HOME/go/bin}"
export PATH="$GO_TOOLS_PATH:$PATH"

# Backend
cd "$ROOT/backend"
uv run uvicorn app.main:app --host "$BACKEND_HOST" --port "$BACKEND_PORT" --reload &
BACKEND_PID=$!
echo "[+] Backend  → http://$BACKEND_HOST:$BACKEND_PORT (PID $BACKEND_PID)"

# Frontend
cd "$ROOT/frontend"
npm run dev -- --host "$FRONTEND_HOST" --port "$FRONTEND_PORT" &
FRONTEND_PID=$!
echo "[+] Frontend → http://$FRONTEND_HOST:$FRONTEND_PORT (PID $FRONTEND_PID)"

echo ""
echo "[+] SRT-Recon running. Ctrl+C to stop."
wait
