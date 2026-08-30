import httpx

from config import ConfigStore
from core.reporting import export_report
from core.services.activity import ActivityService
from core.services.dashboard import DashboardService
from core.services.evidence import EvidenceService
from core.services.findings import FindingsService
from core.services.graph import GraphService
from core.services.diagnostics import DoctorService
from plugins.breach import BreachDB
from plugins.general import GeneralOSINT
from plugins.infra import InfraDNS
from plugins.social import SocialIntel
from plugins.temp_mail import TempMail
from plugins.vuln_finder import VulnFinder
from plugins.web_copy import WebsiteCopier


class ScyllaEngine:
    def __init__(self):
        self.config = ConfigStore()
        timeout = float(self.config.setting("request_timeout_seconds", 10))
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        self.findings = FindingsService()
        self.evidence = EvidenceService()
        self.graph = GraphService()
        self.activity = ActivityService()
        self.dashboard = DashboardService(self.findings, self.evidence, self.graph, self.activity)
        self.doctor = DoctorService()
        self.modules = {
            "vuln": VulnFinder(self.client),
            "social": SocialIntel(self.client),
            "infra": InfraDNS(self.client),
            "general": GeneralOSINT(self.client),
            "breach": BreachDB(self.client),
            "temp": TempMail(self.client),
            "web_copy": WebsiteCopier(self.client),
        }

    async def run_module(self, category, module_id, target, values=None):
        self.activity.log("tool_executed", f"Started {category}/{module_id} for {target}")
        try:
            module = self.modules[category]
            # Pass values to modules that need them (like tempmail)
            module.values = values or {}
            if module_id == "run_all":
                return await module.run_all(target)
            result = await module.run_sub(module_id, target)
            # Some catalog entries are shared by more than one category. Use the
            # general safe-check implementation rather than duplicating handlers.
            if isinstance(result, str) and "not registered" in result.lower():
                return await self.modules["general"].run_sub(module_id, target)
            self._collect_intelligence(module_id, target, result)
            self.activity.log("tool_completed", f"Completed {category}/{module_id} for {target}")
            return result
        except Exception as error:
            self.activity.log("error", f"{category}/{module_id} failed: {type(error).__name__}")
            return f"[!] Error executing module: {type(error).__name__}: {error}"

    def _collect_intelligence(self, module_id, target, result):
        """Convert stable, high-signal existing tool output into local intelligence."""
        text = str(result)
        evidence_id = None
        if text and not text.startswith("[!] Error"):
            evidence = self.evidence.add("tool_output", f"Output from {module_id}", text, target, module_id)
            evidence_id = evidence["id"]
            self.activity.log("evidence_collected", f"Evidence saved from {module_id}")

        if module_id in {"security_headers", "ssl_check", "cookie_audit", "origin_review"}:
            for line in text.splitlines():
                if ("missing" in line.lower() or "not observable" in line.lower() or "not reachable" in line.lower()) and line.startswith("[-]"):
                    title = line[4:].split(":", 1)[0].strip() or "Security hardening opportunity"
                    severity = "MEDIUM" if "content-security" in title.lower() or "cookie" in module_id else "LOW"
                    finding = self.findings.add(title, line[4:].strip(), severity, "web-security", target, [evidence_id] if evidence_id else [], module_id)
                    if evidence_id:
                        evidence_item = self.evidence.view(evidence_id)
                        if evidence_item:
                            evidence_item["finding_id"] = finding["id"]
                            self.evidence.store.set({"counter": (self.evidence.store.get() or {}).get("counter", 0), "items": [evidence_item if item["id"] == evidence_id else item for item in (self.evidence.store.get() or {}).get("items", [])]})
                    self.activity.log("finding_created", f"{title} ({severity})")
        elif module_id in {"secret_scan", "threat_feed_check"} and any(marker in text for marker in ("[-]", "matching report")):
            finding = self.findings.add("Potentially sensitive public configuration discovered", text[:500], "HIGH", "exposure", target, [evidence_id] if evidence_id else [], module_id)
            self.activity.log("finding_created", f"{finding['title']} (HIGH)")

        self._collect_graph(module_id, target, text)

    def _collect_graph(self, module_id, target, text):
        import ipaddress
        from urllib.parse import urlparse
        domain = target.strip().lower()
        parsed = urlparse(domain if "://" in domain else "//" + domain)
        host = parsed.hostname or domain.split("/", 1)[0]
        if not host:
            return
        typ = "ip" if self._is_ip(host) else ("subdomain" if host.count(".") > 1 else "domain")
        root = self.graph.add_node(host, typ, {"source": module_id})
        import re
        for address in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text):
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            ip_node = self.graph.add_node(address, "ip", {"source": module_id})
            self.graph.add_edge(root["id"], ip_node["id"], "resolves_to", {"source": module_id})
        for email in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}", text, re.I):
            email_node = self.graph.add_node(email.lower(), "email", {"source": module_id})
            self.graph.add_edge(root["id"], email_node["id"], "related_to", {"source": module_id})

    @staticmethod
    def _is_ip(value):
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def export(self, result, target, tool):
        paths = export_report(result, target, tool)
        self.activity.log("report_generated", f"Report generated by {tool}")
        return paths

    async def close(self):
        await self.client.aclose()
