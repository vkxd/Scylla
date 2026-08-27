from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from .base import BasePlugin


class SocialIntel(BasePlugin):
    """Public username discovery using user-selected Maigret or Sherlock."""

    async def run_all(self, target):
        return await self.search(target)

    async def run_sub(self, sub_id, target):
        if sub_id in {"sub_sherlock", "alias_search", "maigret", "username_search"}:
            return await self.search(target)
        return "[!] Social tool is not registered."

    async def search(self, target):
        values = getattr(self, "values", {}) or {}
        username = (values.get("username") or target or "").strip().lstrip("@").split()[0]
        method = (values.get("method") or "maigret").strip().lower()
        if not username or len(username) > 64 or any(char in username for char in "\\/\"'`;&|"):
            return "[!] Provide one public username only; never enter a password."
        if method in {"maigret", "m"}:
            return await self._run_maigret(username)
        if method in {"sherlock", "s"}:
            return await self._run_sherlock(username)
        return "[!] Unknown method. Use: maigret or sherlock."

    async def _run_maigret(self, username):
        output_dir = Path(os.environ.get("VELT_OUTPUT_DIR", "outputs")) / "username_checks" / "maigret"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, "-m", "maigret", username, "--json", "ndjson", "--folderoutput", str(output_dir), "--no-progressbar"]
        completed = await self._invoke(command)
        if completed is None:
            return "[!] Maigret timed out."
        report_files = sorted(output_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        found, unknown = self._parse_reports(report_files)
        if completed.returncode != 0 and not report_files:
            return self._process_error("Maigret", completed)
        return self._format_report("Maigret", username, found, unknown, output_dir)

    async def _run_sherlock(self, username):
        output_dir = Path(os.environ.get("VELT_OUTPUT_DIR", "outputs")) / "username_checks" / "sherlock"
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"{username}.txt"
        command = [sys.executable, "-m", "sherlock_project", username, "--output", str(report_path), "--print-found", "--no-color"]
        completed = await self._invoke(command)
        if completed is None:
            return "[!] Sherlock timed out."
        if completed.returncode != 0 and not report_path.exists():
            # Some installs expose Sherlock as `sherlock` rather than the module
            # name used by sherlock-project.
            completed = await self._invoke(["sherlock", username, "--output", str(report_path), "--print-found", "--no-color"])
        if completed is None:
            return "[!] Sherlock timed out."
        if completed.returncode != 0 and not report_path.exists():
            return self._process_error("Sherlock", completed, "pip install sherlock-project")
        urls = []
        if report_path.exists():
            urls = [line.strip() for line in report_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip().startswith(("http://", "https://"))]
        if not urls:
            urls = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip().startswith(("http://", "https://"))]
        return self._format_report("Sherlock", username, [("Public profile", url) for url in sorted(set(urls))], 0, output_dir)

    async def _invoke(self, command):
        def invoke():
            import subprocess
            env = os.environ.copy()
            env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
            return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=900)
        try:
            return await asyncio.to_thread(invoke)
        except Exception as error:
            if type(error).__name__ == "TimeoutExpired":
                return None
            raise

    @staticmethod
    def _parse_reports(report_files):
        found = []
        unknown = 0
        for report in report_files:
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
                items = data.get("sites", data) if isinstance(data, dict) else data
                if isinstance(items, dict):
                    items = items.values()
                for item in items or []:
                    if not isinstance(item, dict):
                        continue
                    status = str(item.get("status", item.get("status_code", ""))).lower()
                    url = item.get("url_user") or item.get("url") or item.get("link")
                    if url and any(marker in status for marker in ("found", "claimed", "true", "available")):
                        found.append((item.get("site") or item.get("name") or "Public profile", url))
                    elif any(marker in status for marker in ("unknown", "error", "timeout", "blocked")):
                        unknown += 1
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(set(found)), unknown

    @staticmethod
    def _format_report(method, username, found, unknown, output_dir):
        lines = [f"[>] {method} public username search: {username}", "[!] Results are public-page matches, not proof of identity or account ownership.", f"[>] Full report folder: {output_dir}"]
        lines.extend(f"[+] {site}: {url}" for site, url in found)
        if not found:
            lines.append(f"[-] No public profiles were confirmed by {method}.")
        lines.extend([f"[+] Confirmed public profiles: {len(found)}", f"[!] Unverified/blocked checks: {unknown}"])
        return "\n".join(lines)

    @staticmethod
    def _process_error(name, completed, install="pip install maigret"):
        details = (completed.stderr or completed.stdout or "No output returned.").strip()
        return "\n".join([f"[!] {name} did not complete.", details[-3000:], f"[>] Install or verify it with: {install}"])
