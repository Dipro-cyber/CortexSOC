#!/usr/bin/env bash
set -euo pipefail

API=${API_URL:-http://localhost:8000}
FRONTEND=${FRONTEND_URL:-http://localhost:5173}
SIGNOZ=${SIGNOZ_URL:-http://localhost:3301}

check() {
  local name=$1 url=$2
  if curl -sf --max-time 5 "$url" > /dev/null 2>&1; then
    echo "✅  $name ($url)"
  else
    echo "❌  $name ($url)"
  fi
}

echo "=== CortexSOC Health Check ==="
check "Backend /health"  "$API/health"
check "Frontend"          "$FRONTEND"
check "SigNoz"            "$SIGNOZ"
echo "=============================="
