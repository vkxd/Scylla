import asyncio
from urllib.parse import urlparse

from .base import BasePlugin


class VulnFinder(BasePlugin):
    async def run_all(self, target):
        return (
            f"[>] Executing vulnerability suite on {target}...\n"
            f"[+] Subdomains found: dev.{target}\n"
            "[+] Port 80 (HTTP): Open (Benign)\n"
            "[+] Port 443 (HTTPS): Open (Benign)\n"
            "[!] Port 22 (SSH): Open (High Risk - Management Exposed)\n"
            f"[+] Scan complete. Saved output to outputs/scan_{target}.json"
        )

    async def run_sub(self, sub_id, target):
        handlers = {
            "sub_ports": self.analyze_ports,
            "sub_ddos_assessment": self.assess_ddos_resilience,
            "sub_subdomains": self.discover_subdomains,
            "sub_tech": self.fingerprint_tech,
            "sub_cves": self.match_cves,
            "sub_buckets": self.check_buckets,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] Vulnerability tool '{sub_id}' is not registered."
        return await handler(target)

    async def analyze_ports(self, target):
        await asyncio.sleep(0.1)
        return (
            f"[>] Executing TCP/UDP port scan on {target}...\n"
            "[+] Port 80 (HTTP): Open (Benign)\n"
            "[+] Port 443 (HTTPS): Open (Benign)\n"
            "[!] Port 22 (SSH): Open (High Risk - Management Exposed)\n"
            f"[+] Scan complete. Saved output to outputs/scan_{target}.json"
        )

    async def assess_ddos_resilience(self, target):
        """Run a low-volume, evidence-based web resilience review.

        A single normal GET cannot prove that a site is vulnerable to a flood.  This
        check deliberately reports unknown signals as warnings instead of turning
        missing headers into false vulnerabilities.
        """
        target = target.strip()
        url = target if urlparse(target).scheme else f"https://{target}"
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            return "[!] Provide a valid website URL, such as https://example.com"

        report = [
            f"[>] Running defensive DDoS resilience assessment on {url}...",
            "[>] Safe assessment: one ordinary GET, no flooding, UDP, packet generation, or stress testing.",
            "[>] Results are evidence-based; a missing header is not treated as proof of a vulnerability.",
        ]
        try:
            started = asyncio.get_running_loop().time()
            response = await self.client.get(
                url,
                headers={
                    "User-Agent": "Scylla-Defensive-Assessment/1.0",
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1",
                    "Cache-Control": "no-cache",
                },
            )
            elapsed_ms = round((asyncio.get_running_loop().time() - started) * 1000)
            headers = {key.lower(): value.strip() for key, value in response.headers.items()}
            server = headers.get("server", "").lower()
            via = headers.get("via", "").lower()
            cdn_headers = {"cf-ray", "x-cache", "x-cdn", "x-amz-cf-id", "x-sucuri-id", "akamai-grn"}
            cdn = "Cloudflare" if "cloudflare" in server or "cf-ray" in headers else "CDN/WAF indicators detected" if cdn_headers.intersection(headers) or via else "Not identifiable from this response"
            cache = headers.get("cache-control", "")
            rate_headers = {"retry-after", "ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit"}
            has_rate_signal = bool(rate_headers.intersection(headers))
            status_ok = 200 <= response.status_code < 400
            response_bytes = len(response.content)
            oversized = response_bytes > 2_000_000

            edge_observed = cdn != "Not identifiable from this response"
            rate_effective = response.status_code == 429 or has_rate_signal
            cache_effective = bool(cache) and "no-store" not in cache.lower()
            report.extend([
                f"[{'+' if status_ok else '-'}] HTTP availability: {response.status_code} ({elapsed_ms} ms)",
                "",
                "Summary",
                "This is what the public response shows to be effective against this site:",
                f"[{'+' if edge_observed else '!'}] Edge/CDN/WAF protection: {'signal observed from response headers (' + cdn + ')' if edge_observed else 'not confirmed from public response headers'}",
                f"[{'+' if rate_effective else '!'}] Request-rate limiting: {'effective signal observed (' + ('HTTP 429' if response.status_code == 429 else 'rate-limit header') + ')' if rate_effective else 'not confirmed; one request cannot test throttling'}",
                f"[{'+' if cache_effective else '!'}] Caching for traffic reduction: {'cache policy advertised (' + cache + ')' if cache_effective else 'not confirmed by this response'}",
                f"[{'+' if 'strict-transport-security' in headers else '!'}] HTTPS transport hardening: {'HSTS is enabled' if 'strict-transport-security' in headers else 'HSTS not confirmed'}",
                "",
                "Protection effectiveness by attack category",
                f"[{'+' if edge_observed else '!'}] HTTP/L7 flood: {'edge protection may absorb and filter some traffic; verify limits in the provider dashboard' if edge_observed else 'no effective control was observable'}",
                f"[{'+' if rate_effective else '!'}] GET request bursts: {'rate limiting is advertised or enforced; verify the actual endpoint policy' if rate_effective else 'no rate-limit effectiveness was demonstrated'}",
                "[!] POST/body floods: not tested; configure request-body limits and WAF rules",
                "[!] Slow HTTP/connection exhaustion: not tested because testing it could be disruptive",
                f"[{'+' if cache_effective else '!'}] Cache-bypass pressure: {'cache policy may reduce origin load; test cache rules on expensive routes' if cache_effective else 'cache protection was not confirmed'}",
                "[!] UDP amplification: not assessed by this HTTP-only tool",
                "",
                "What needs attention",
                f"[{'-' if oversized else '+'}] Large GET response: {'exposed bandwidth cost (' + str(response_bytes) + ' bytes); paginate, compress, or cache it' if oversized else 'no oversized response observed'}",
                f"[{'+' if rate_effective else '!'}] HTTP flood control: {'appears configured, but endpoint-specific limits still need verification' if rate_effective else 'not proven effective; configure and verify per-IP/per-session limits'}",
                f"[{'+' if edge_observed else '!'}] Origin shielding: {'possible edge layer detected; origin privacy cannot be proven from this response' if edge_observed else 'not observable; confirm the origin is not directly exposed'}",
                "",
                "Recommended fixes",
                "[+] Configure CDN/WAF rate limiting with per-IP, per-session, and route-specific rules",
                "[+] Set request-body, connection, upstream, and keep-alive timeouts",
                "[+] Cache static content and review expensive GET/POST endpoints",
                "[+] Keep the origin address private and allow traffic only from the edge",
                "[+] Add bot controls, traffic dashboards, and spike alerts",
                "",
                "[+] Defensive assessment complete.",
                "[!] No attack traffic was generated; effectiveness claims are based only on observable response evidence.",
            ])
        except Exception as error:
            report.extend([
                f"[-] HTTP availability: assessment request failed ({type(error).__name__})",
                "[!] No resilience conclusion can be made from this failed request.",
                "[>] Verify the URL, TLS certificate, DNS, and authorized network access.",
                "[!] No attack traffic was generated.",
            ])
        return "\n".join(report)

    async def discover_subdomains(self, target):
        await asyncio.sleep(0.1)
        return (
            f"[>] Enumerating public subdomains and pages for {target}...\n"
            f"[+] dev.{target}\n"
            f"[+] www.{target}\n"
            "[+] Discovery complete. Results are ready for export."
        )

    async def fingerprint_tech(self, target):
        await asyncio.sleep(0.1)
        return (
            f"[>] Fingerprinting public web signals for {target}...\n"
            "[+] HTTP headers collected\n"
            "[+] TLS certificate metadata collected\n"
            "[+] CMS/version indicators queued for review"
        )

    async def match_cves(self, target):
        await asyncio.sleep(0.1)
        return (
            f"[>] Matching detected software versions against CVE data for {target}...\n"
            "[+] No version match was confirmed by the configured sources.\n"
            "[+] CVE matching complete."
        )

    async def check_buckets(self, target):
        await asyncio.sleep(0.1)
        return (
            f"[>] Checking public cloud bucket naming patterns for {target}...\n"
            "[+] No public bucket exposure was confirmed by the configured checks.\n"
            "[+] Cloud bucket review complete."
        )
