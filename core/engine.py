import httpx

from plugins.breach import BreachDB
from plugins.infra import InfraDNS
from plugins.social import SocialIntel
from plugins.temp_mail import TempMail
from plugins.vuln_finder import VulnFinder


class ScyllaEngine:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        self.modules = {
            "vuln": VulnFinder(self.client),
            "social": SocialIntel(self.client),
            "infra": InfraDNS(self.client),
            "breach": BreachDB(self.client),
            "temp": TempMail(self.client),
        }

    async def run_module(self, category, module_id, target):
        try:
            if module_id == "run_all":
                return await self.modules[category].run_all(target)
            return await self.modules[category].run_sub(module_id, target)
        except Exception as error:
            return f"[!] Error executing module: {error}"
