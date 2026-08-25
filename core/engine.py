import httpx

from config import ConfigStore
from core.reporting import export_report
from plugins.breach import BreachDB
from plugins.general import GeneralOSINT
from plugins.infra import InfraDNS
from plugins.social import SocialIntel
from plugins.temp_mail import TempMail
from plugins.vuln_finder import VulnFinder


class ScyllaEngine:
    def __init__(self):
        self.config = ConfigStore()
        timeout = float(self.config.setting("request_timeout_seconds", 10))
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        self.modules = {
            "vuln": VulnFinder(self.client),
            "social": SocialIntel(self.client),
            "infra": InfraDNS(self.client),
            "general": GeneralOSINT(self.client),
            "breach": BreachDB(self.client),
            "temp": TempMail(self.client),
        }

    async def run_module(self, category, module_id, target, values=None):
        try:
            module = self.modules[category]
            # Pass values to modules that need them (like tempmail)
            if values:
                module.values = values
            if module_id == "run_all":
                return await module.run_all(target)
            result = await module.run_sub(module_id, target)
            # Some catalog entries are shared by more than one category. Use the
            # general safe-check implementation rather than duplicating handlers.
            if isinstance(result, str) and "not registered" in result.lower():
                return await self.modules["general"].run_sub(module_id, target)
            return result
        except Exception as error:
            return f"[!] Error executing module: {type(error).__name__}: {error}"

    def export(self, result, target, tool):
        return export_report(result, target, tool)

    async def close(self):
        await self.client.aclose()
