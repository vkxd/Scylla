from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from .base import BasePlugin


class WebsiteCopier(BasePlugin):
    """Run the user's supplied Playwright website copier script."""

    async def run_all(self, target):
        return await self.copy(target)

    async def run_sub(self, sub_id, target):
        if sub_id in {"website_copy", "site_copy", "web_copy"}:
            return await self.copy(target)
        return "[!] Website copier is not registered."

    async def copy(self, target):
        project_root = Path(__file__).resolve().parents[2]
        script_candidates = (
            project_root / "website_copyper_ script.py",
            project_root / "website_copier_script.py",
            project_root / "website_copyper_script.py",
        )
        script = next((candidate for candidate in script_candidates if candidate.is_file()), None)
        if script is None:
            return "[!] Copier script not found in the project root."

        url = target.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            return "[!] Provide a valid website URL."

        output_base = Path(os.environ.get("VELT_OUTPUT_DIR", project_root / "outputs"))
        output_dir = output_base / "website_copies" / self._safe(parsed.netloc)
        output_dir.mkdir(parents=True, exist_ok=True)

        def invoke():
            import subprocess

            # The supplied script asks for URL and export folder through input().
            answers = url + "\n" + str(output_dir) + "\n"
            env = os.environ.copy()
            env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
            return subprocess.run(
                [sys.executable, str(script)],
                input=answers,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                cwd=str(script.parent),
                env=env,
                timeout=900,
            )

        try:
            completed = await asyncio.to_thread(invoke)
        except Exception as error:
            if type(error).__name__ == "TimeoutExpired":
                return f"[!] Copier timed out. Partial output may remain in {output_dir}."
            return f"[!] Copier could not start: {type(error).__name__}: {error}"

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        if completed.returncode != 0:
            details = stderr or stdout or "No output returned by the copier."
            return "\n".join([
                "[-] The supplied website copier exited with an error.",
                details[-5000:],
                f"[>] Output folder: {output_dir}",
                "[>] If Playwright is missing, run: pip install playwright && playwright install chromium",
            ])

        return "\n".join([
            "[+] Supplied Playwright website copier completed.",
            stdout[-6000:] if stdout else "[+] Export completed.",
            f"[+] Output folder: {output_dir}",
        ])

    @staticmethod
    def _safe(value):
        return re.sub(r"[^a-zA-Z0-9._-]", "_", value)

    @staticmethod
    def _resource_name(url, content_type):
        parsed = urlparse(url)
        base = re.sub(r"[^a-zA-Z0-9._-]", "_", Path(parsed.path).name or "resource")
        stem = Path(base).stem
        ext = Path(base).suffix or mimetypes.guess_extension(content_type.split(";", 1)[0]) or ".bin"
        digest = hashlib.sha256(url.encode()).hexdigest()[:12]
        return f"{stem}_{digest}{ext}"
