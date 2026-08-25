from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"
CONFIG_PATH = ROOT / "config.json"

PROVIDER_ENV = {
    "shodan": "SHODAN_API_KEY",
    "hibp": "HIBP_API_KEY",
    "github": "GITHUB_TOKEN",
    "search": "SERPAPI_KEY",
    "geocoding": "OPENCAGE_API_KEY",
    "nvd": "NVD_API_KEY",
}


class ConfigStore:
    """Loads user-owned provider keys without ever exposing full secrets to the UI."""

    def __init__(self, env_path: Path = ENV_PATH, config_path: Path = CONFIG_PATH):
        self.env_path = env_path
        self.config_path = config_path
        self._values: Dict[str, Any] = {}
        self._env_keys: Dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        self._values = self._read_json()
        if not isinstance(self._values, dict):
            self._values = {}
        self._values.setdefault("providers", {})
        self._values.setdefault("settings", {})
        env_values = self._read_env()
        self._env_keys = {
            provider: env_values.get(env_name) or os.getenv(env_name, "")
            for provider, env_name in PROVIDER_ENV.items()
        }

    def _read_env(self) -> Dict[str, str]:
        if not self.env_path.exists():
            return {}
        values: Dict[str, str] = {}
        for raw_line in self.env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip("\"'")
        return values

    def _read_json(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {}
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def provider_key(self, provider: str) -> str:
        # Environment values take precedence, but are kept out of config.json.
        if self._env_keys.get(provider):
            return self._env_keys[provider]
        value = self._values.get("providers", {}).get(provider, {})
        if isinstance(value, dict):
            return str(value.get("api_key") or value.get("token") or "")
        return ""

    def provider_status(self, provider: str) -> str:
        return "configured" if self.provider_key(provider) else "not configured"

    def masked_key(self, provider: str) -> str:
        key = self.provider_key(provider)
        if not key:
            return "not configured"
        return "*" * max(8, len(key) - 4) + key[-4:]

    def setting(self, name: str, default: Any = None) -> Any:
        return self._values.get("settings", {}).get(name, default)

    def set_provider_key(self, provider: str, key: str) -> None:
        if provider not in PROVIDER_ENV:
            raise ValueError(f"Unknown provider: {provider}")
        self._values.setdefault("providers", {}).setdefault(provider, {})["api_key"] = key.strip()

    def set_setting(self, name: str, value: Any) -> None:
        self._values.setdefault("settings", {})[name] = value

    def save(self) -> None:
        # Persist only values explicitly entered in the local config file; never
        # copy secrets loaded from the process environment into that file.
        self.config_path.write_text(
            json.dumps(self._values, indent=2) + "\n", encoding="utf-8"
        )
        try:
            os.chmod(self.config_path, 0o600)
        except OSError:
            pass

    def provider_summary(self) -> Dict[str, str]:
        return {provider: self.provider_status(provider) for provider in PROVIDER_ENV}

    def redacted_summary(self) -> Dict[str, str]:
        return {provider: self.masked_key(provider) for provider in PROVIDER_ENV}
