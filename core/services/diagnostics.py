"""VeltCLI installation diagnostics."""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

from config import CONFIG_PATH, PROVIDER_ENV


class DoctorService:
    def __init__(self, root: Path | None = None):
        self.root = root or Path(__file__).resolve().parents[2]

    def checks(self) -> list[dict]:
        results = []
        major, minor = sys.version_info[:2]
        results.append({"level": "ok" if (major, minor) >= (3, 10) else "critical", "label": "Python version", "detail": f"{major}.{minor} ({'compatible' if (major, minor) >= (3, 10) else 'requires Python 3.10+'})"})
        required = {"httpx": "httpx", "textual": "textual", "rich": "rich", "dns": "dnspython"}
        missing = [package for package, module in required.items() if importlib.util.find_spec(module) is None]
        results.append({"level": "ok" if not missing else "critical", "label": "Core dependencies", "detail": "installed" if not missing else "missing: " + ", ".join(missing)})
        config_ok = True
        try:
            if CONFIG_PATH.exists():
                import json
                config_ok = isinstance(json.loads(CONFIG_PATH.read_text(encoding="utf-8")), dict)
        except (OSError, ValueError):
            config_ok = False
        results.append({"level": "ok" if config_ok else "critical", "label": "Configuration", "detail": "valid" if config_ok else "config.json is not valid JSON"})
        output = self.root / "outputs"
        try:
            output.mkdir(parents=True, exist_ok=True)
            probe = output / ".velt-doctor-write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            writable = True
        except OSError:
            writable = False
        results.append({"level": "ok" if writable else "critical", "label": "Output directory", "detail": str(output) + (" writable" if writable else " is not writable")})
        required_files = ["main.py", "config.py", "core/engine.py", "ui/workflow.py"]
        missing_files = [name for name in required_files if not (self.root / name).is_file()]
        results.append({"level": "ok" if not missing_files else "critical", "label": "Project files", "detail": "present" if not missing_files else "missing: " + ", ".join(missing_files)})
        for provider, env_name in PROVIDER_ENV.items():
            if not os.getenv(env_name):
                results.append({"level": "warning", "label": env_name, "detail": "not configured (optional feature unavailable)"})
        return results

    def render(self) -> str:
        lines = ["╭──────────────────────────────────────╮", "│           VELTCLI DOCTOR              │", "╰──────────────────────────────────────╯"]
        symbols = {"ok": "✓", "warning": "⚠", "critical": "✗"}
        for result in self.checks():
            lines.append(f"{symbols[result['level']]} {result['label']}: {result['detail']}")
        critical = any(result["level"] == "critical" for result in self.checks())
        lines.append("✗ VeltCLI has critical issues to resolve." if critical else "✓ VeltCLI is ready")
        return "\n".join(lines)
