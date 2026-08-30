"""Evidence — structured supporting data referenced by findings."""
from __future__ import annotations

from datetime import datetime, timezone

from .store import JsonStore

MAX_EVIDENCE = 500


class EvidenceService:
    def __init__(self, store: JsonStore | None = None):
        self.store = store or JsonStore("evidence")

    def add(self, kind: str, summary: str, observed: str = "",
            target: str = "", source: str = "", raw: dict | None = None,
            finding_id: str | None = None) -> dict:
        """kind: url | headers | dns | metadata | tool_output | note"""
        data = self.store.get() or {"counter": 0, "items": []}
        data["counter"] = int(data.get("counter", 0)) + 1
        item = {
            "id": f"EVID-{data['counter']:04d}",
            "kind": kind,
            "summary": summary[:300],
            "observed": observed[:2000],  # structured, useful — not raw dumps
            "target": target,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": source,
            "finding_id": finding_id,
            "raw": raw or {},
        }
        items = data.get("items", [])
        items.append(item)
        data["items"] = items[-MAX_EVIDENCE:]
        self.store.set(data)
        return item

    def list(self) -> list[dict]:
        return list(reversed((self.store.get() or {}).get("items", [])))

    def view(self, evidence_id: str) -> dict | None:
        for item in (self.store.get() or {}).get("items", []):
            if item["id"].lower() == evidence_id.strip().lower():
                return item
        return None

    def export(self, evidence_id: str) -> dict | None:
        item = self.view(evidence_id)
        if item is None:
            return None
        return {
            "evidence": item,
            "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "app": "VeltCLI",
        }

    def count(self) -> int:
        return len((self.store.get() or {}).get("items", []))

    def clear(self) -> int:
        data = self.store.get() or {}
        count = len(data.get("items", []))
        self.store.set({"counter": data.get("counter", 0), "items": []})
        return count
