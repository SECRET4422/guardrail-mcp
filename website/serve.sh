#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "Serving GuardRail site at http://127.0.0.1:${1:-8080}"
python3 -m http.server "${1:-8080}"
