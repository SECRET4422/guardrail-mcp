#!/usr/bin/env bash
# Smoke-test STDIO server with NDJSON framing (simple clients).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

python - "$ROOT" <<'PY'
import json, subprocess, sys
from pathlib import Path

root = Path(sys.argv[1])
proc = subprocess.Popen(
    [sys.executable, "-m", "guardrail", "--mode", "stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd=str(root),
)

def send(obj):
    line = json.dumps(obj) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()

def recv():
    line = proc.stdout.readline()
    if not line:
        err = proc.stderr.read().decode()
        raise RuntimeError(f"EOF from server. stderr={err}")
    return json.loads(line.decode())

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "smoke", "version": "0"},
}})
print("initialize ->", json.dumps(recv(), indent=2)[:400], "...")

send({"jsonrpc": "2.0", "method": "notifications/initialized"})
# no response expected

send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools = recv()
print("tools ->", [t["name"] for t in tools["result"]["tools"]])

send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
    "name": "audit_code_safety",
    "arguments": {"source_code": "password = \"hunter2hunter2\"\neval(x)\n"},
}})
print("call ->", recv()["result"]["content"][0]["text"][:500], "...")

proc.stdin.close()
proc.terminate()
proc.wait(timeout=5)
print("OK")
PY
