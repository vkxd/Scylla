"""Shared local JSON persistence for VeltCLI services.

All service state lives under outputs/data/ so it survives restarts and sits
next to the reports the user already knows about. Writes are atomic
(temp file + rename) so a crash never leaves a corrupt store behind.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

DATA_DIR = Path("outputs") / "data"


class JsonStore:
    """Tiny append/replace JSON document store with atomic writes."""

    def __init__(self, name: str, data_dir: Path | None = None):
        self.data_dir = Path(data_dir) if data_dir else DATA_DIR
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / f"{name}.json"
        self._cache: Any = None
        self._loaded = False

    def _load(self) -> Any:
        if self._loaded:
            return self._cache
        self._loaded = True
        if not self.path.exists():
            self._cache = None
            return None
        try:
            self._cache = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A corrupt store must never brick the app; start fresh but keep
            # the broken file aside for manual recovery.
            try:
                self.path.rename(self.path.with_suffix(".json.corrupt"))
            except OSError:
                pass
            self._cache = None
        return self._cache

    def _save(self, value: Any) -> None:
        self._cache = value
        self._loaded = True
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self.data_dir), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=1, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass  # storage failures degrade to in-memory only, never crash a tool

    def get(self) -> Any:
        return self._load()

    def set(self, value: Any) -> None:
        self._save(value)
