"""
Incremental scanning cache — skip unchanged files via content hash.

Cache format (JSON):
  {
    "version": 1,
    "entries": {
      "<abs-path>": {"sha256": "...", "mtime": ..., "result": {...}}
    }
  }
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


CACHE_VERSION = 1
DEFAULT_CACHE = ".guardrail_cache.json"


class ScanCache:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(
            path
            or os.environ.get("GUARDRAIL_CACHE_PATH")
            or DEFAULT_CACHE
        )
        self._lock = threading.Lock()
        self._data: Dict[str, Any] = {"version": CACHE_VERSION, "entries": {}}
        self.hits = 0
        self.misses = 0
        self._load()

    def _load(self) -> None:
        if self.path.is_file():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
                if self._data.get("version") != CACHE_VERSION:
                    self._data = {"version": CACHE_VERSION, "entries": {}}
            except Exception:
                self._data = {"version": CACHE_VERSION, "entries": {}}

    def save(self) -> None:
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(self.path.suffix + ".tmp")
                tmp.write_text(json.dumps(self._data), encoding="utf-8")
                tmp.replace(self.path)
            except OSError:
                pass

    @staticmethod
    def file_fingerprint(path: Path) -> Tuple[str, float]:
        st = path.stat()
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 256), b""):
                h.update(chunk)
        return h.hexdigest(), st.st_mtime

    def get(self, path: Path) -> Optional[Dict[str, Any]]:
        key = str(path.resolve())
        with self._lock:
            ent = (self._data.get("entries") or {}).get(key)
            if not ent:
                self.misses += 1
                return None
            try:
                sha, mtime = self.file_fingerprint(path)
            except OSError:
                self.misses += 1
                return None
            if ent.get("sha256") == sha and abs(float(ent.get("mtime", 0)) - mtime) < 1e-6:
                self.hits += 1
                return ent.get("result")
            self.misses += 1
            return None

    def put(self, path: Path, result: Dict[str, Any]) -> None:
        key = str(path.resolve())
        try:
            sha, mtime = self.file_fingerprint(path)
        except OSError:
            return
        with self._lock:
            self._data.setdefault("entries", {})[key] = {
                "sha256": sha,
                "mtime": mtime,
                "saved_at": time.time(),
                "result": result,
            }

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "path": str(self.path),
                "entries": len(self._data.get("entries") or {}),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / max(1, self.hits + self.misses), 3),
            }


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
