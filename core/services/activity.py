"""Activity history — lightweight event log backing the dashboard."""
from __future__ import annotations

from datetime import datetime, timezone

from .store import JsonStore

MAX_EVENTS = 200  # keep storage efficient; the dashboard only shows recent


class ActivityService:
    def __init__(self, store: JsonStore | None = None):
        self.store = store or JsonStore("activity")

    def log(self, event_type: str, description: str) -> None:
        data = self.store.get() or {"events": []}
        events = data.get("events", [])
        events.append({
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "type": event_type,
            "description": description[:200],
        })
        data["events"] = events[-MAX_EVENTS:]
        self.store.set(data)

    def recent(self, limit: int = 10) -> list[dict]:
        data = self.store.get() or {}
        events = data.get("events", [])
        return list(reversed(events[-limit:]))

    def clear(self) -> int:
        data = self.store.get() or {}
        count = len(data.get("events", []))
        self.store.set({"events": []})
        return count

    def count(self) -> int:
        return len((self.store.get() or {}).get("events", []))
