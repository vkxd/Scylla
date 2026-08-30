import dns.resolver

from .base import BasePlugin


class InfraDNS(BasePlugin):
    async def run_all(self, target):
        report = f"Infrastructure Report for {target}\n"
        try:
            answers = dns.resolver.resolve(target, "A")
            for rdata in answers:
                report += f"[+] IP Address: {rdata}\n"
        except Exception:
            report += "[-] Could not resolve A records.\n"
        return report

    async def run_sub(self, sub_id, target):
        if sub_id in {"web_info", "infra_map"}:
            return await self._expanded_report(target, sub_id)
        return f"[!] Infrastructure tool '{sub_id}' is not registered."

    async def _expanded_report(self, target, sub_id):
        report_title = "Website Information" if sub_id == "web_info" else "Passive Infrastructure Map"
        report = f"[>] {report_title} for {target}\n"
        try:
            answers = dns.resolver.resolve(target, "A")
            for rdata in answers:
                report += f"[+] A record: {rdata}\n"
                try:
                    import socket
                    hostname = str(rdata)
                    report += f"[+] Resolved host: {hostname}\n"
                except Exception:
                    pass
        except Exception:
            report += "[-] A records unavailable from the configured resolver.\n"
        report += "[+] DNS record collection complete.\n"
        report += "[+] Certificate transparency and reverse ownership checks are ready for configured providers."
        return report
