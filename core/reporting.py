from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|token|authorization|password|secret)(\s*[:=]\s*)\S+")


def redact(text: str) -> str:
    return SECRET_PATTERN.sub(r"\1\2[REDACTED]", text)


def safe_lines(result: str) -> list[str]:
    return [redact(line) for line in str(result).splitlines()]


def export_report(result: str, target: str, tool: str, output_dir: str = "outputs") -> dict[str, str]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = re.sub(r"[^a-zA-Z0-9_-]+", "_", f"{tool}_{target}").strip("_")[:80] or "scylla_report"
    lines = safe_lines(result)
    metadata = {"tool": tool, "target": redact(target), "created_at": stamp, "findings": lines}
    paths = {
        "json": directory / f"{stem}_{stamp}.json",
        "csv": directory / f"{stem}_{stamp}.csv",
        "md": directory / f"{stem}_{stamp}.md",
    }
    paths["json"].write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    with paths["csv"].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["status", "finding"])
        for line in lines:
            writer.writerow([line[:3] if line[:3] in {"[+]", "[-]", "[!]"} else "", line])
    paths["md"].write_text(
        f"# Scylla Report\n\n- Tool: `{tool}`\n- Target: `{redact(target)}`\n- Created: `{stamp}`\n\n" + "\n".join(f"- {line}" for line in lines) + "\n",
        encoding="utf-8",
    )
    return {kind: str(path) for kind, path in paths.items()}
