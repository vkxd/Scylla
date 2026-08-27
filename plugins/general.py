from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .base import BasePlugin


class GeneralOSINT(BasePlugin):
    """Safe public-information and local-file helpers for the expanded catalog."""

    async def run_all(self, target):
        return await self.run_sub("security_headers", target)

    async def run_sub(self, sub_id, target):
        handlers = {
            "security_headers": self.security_headers,
            "ssl_check": self.ssl_check,
            "redirect_checker": self.redirect_checker,
            "robots_analyzer": self.robots_analyzer,
            "sitemap_analyzer": self.sitemap_analyzer,
            "cookie_audit": self.cookie_audit,
            "email_domain_info": self.email_domain_info,
            "spf_check": self.spf_check,
            "dmarc_check": self.dmarc_check,
            "dnssec_check": self.dnssec_check,
            "ip_info": self.ip_info,
            "reverse_dns": self.reverse_dns,
            "company_profile": self.company_profile,
            "coordinate_info": self.coordinate_info,
            "image_metadata": self.image_metadata,
            "document_metadata": self.document_metadata,
            "file_inventory": self.file_inventory,
            "uptime_check": self.uptime_check,
            "article_summary": self.article_summary,
            "place_search": self.place_search,
            "network_range": self.provider_placeholder,
            "whois_lookup": self.whois_lookup,
            "website_copy": self.provider_placeholder,
            "subdomain_enum": self.subdomain_enum,
            "tech_detect": self.tech_detect,
            "certificate_history": self.certificate_history,
            "asn_details": self.asn_details,
            "email_discovery": self.email_discovery,
            "port_services": self.port_services,
            "threat_feed_check": self.threat_feed_check,
            "certificate_search": self.provider_placeholder,
            "asn_map": self.provider_placeholder,
            "storage_review": self.provider_placeholder,
            "cloud_service_map": self.cloud_service_map,
            "origin_review": self.origin_review,
            "profile_summary": self.article_summary,
            "public_links": self.public_links,
            "timeline_notes": self.local_timeline,
            "article_search": self.provider_placeholder,
            "source_compare": self.local_timeline,
            "timeline_builder": self.local_timeline,
            "brand_monitor": self.provider_placeholder,
            "product_research": self.article_summary,
            "metadata_cleaner": self.local_file_guidance,
            "ocr": self.local_file_guidance,
            "text_extract": self.local_file_guidance,
            "dependency_audit": self.local_file_guidance,
            "secret_scan": self.secret_scan,
            "header_analyzer": self.local_file_guidance,
            "certificate_expiry": self.provider_placeholder,
            "exposure_diff": self.local_timeline,
        }
        handler = handlers.get(sub_id)
        if handler is None:
            return f"[!] This catalog tool is planned but not implemented yet: {sub_id}"
        return await handler(target)

    def _url(self, target: str) -> str:
        return target if urlparse(target).scheme else f"https://{target}"

    async def security_headers(self, target):
        url = self._url(target)
        response = await self.client.get(url, headers={"User-Agent": "Scylla-Defensive-Review/1.0"})
        headers = {key.lower(): value for key, value in response.headers.items()}
        checks = {
            "Content-Security-Policy": "content-security-policy",
            "Strict-Transport-Security": "strict-transport-security",
            "X-Content-Type-Options": "x-content-type-options",
            "X-Frame-Options": "x-frame-options",
            "Referrer-Policy": "referrer-policy",
            "Permissions-Policy": "permissions-policy",
        }
        lines = [f"[>] Browser security-header review for {url} ({response.status_code})", "What this means: headers tell browsers which defensive rules to enforce."]
        for label, key in checks.items():
            lines.append(f"[{'+' if key in headers else '-'}] {label}: {headers.get(key, 'missing')}")
        lines.append("[+] Review complete. Missing headers are hardening opportunities, not proof of compromise.")
        return "\n".join(lines)

    async def ssl_check(self, target):
        url = self._url(target)
        parsed = urlparse(url)
        response = await self.client.get(url, headers={"User-Agent": "Scylla-TLS-Review/1.0"})
        hsts = response.headers.get("strict-transport-security")
        return "\n".join([
            f"[>] TLS and HTTPS review for {url}",
            f"[{'+' if parsed.scheme == 'https' else '-'}] HTTPS scheme: {parsed.scheme}",
            f"[{'+' if hsts else '!'}] HSTS: {hsts or 'not observable from response'}",
            "[+] Certificate details should be checked with the browser or certificate provider for full chain validation.",
        ])

    async def redirect_checker(self, target):
        url = self._url(target)
        response = await self.client.get(url, follow_redirects=False, headers={"User-Agent": "Scylla-Redirect-Review/1.0"})
        location = response.headers.get("location")
        return "\n".join([
            f"[>] Redirect review for {url}",
            f"[+] Initial response: {response.status_code}",
            f"[{'+' if not location else '!'}] Redirect target: {location or 'none'}",
            "[!] Review cross-domain redirects manually before trusting them.",
        ])

    async def robots_analyzer(self, target):
        url = urljoin(self._url(target).rstrip("/") + "/", "robots.txt")
        response = await self.client.get(url, headers={"User-Agent": "Scylla-Public-Review/1.0"})
        paths = [line.split(":", 1)[1].strip() for line in response.text.splitlines() if line.lower().startswith(("disallow:", "allow:")) and ":" in line]
        return "\n".join([f"[>] Public robots.txt review: {url}", f"[{'+' if response.status_code == 200 else '!'}] HTTP response: {response.status_code}", f"[+] Rules found: {len(paths)}", "[!] robots.txt is a crawler preference file, not an access-control mechanism."])

    async def sitemap_analyzer(self, target):
        url = urljoin(self._url(target).rstrip("/") + "/", "sitemap.xml")
        response = await self.client.get(url, headers={"User-Agent": "Scylla-Public-Review/1.0"})
        urls = re.findall(r"<loc>\s*(.*?)\s*</loc>", response.text, re.I)
        return "\n".join([f"[>] Public sitemap review: {url}", f"[{'+' if response.status_code == 200 else '!'}] HTTP response: {response.status_code}", f"[+] URLs listed: {len(urls)}"])

    async def cookie_audit(self, target):
        response = await self.client.get(self._url(target), headers={"User-Agent": "Scylla-Cookie-Review/1.0"})
        cookies = response.headers.get_list("set-cookie")
        lines = [f"[>] Cookie flag review ({len(cookies)} cookies observed)"]
        for cookie in cookies:
            name = cookie.split("=", 1)[0]
            flags = cookie.lower()
            lines.append(f"[{'+' if 'secure' in flags else '-'}] {name}: Secure={'yes' if 'secure' in flags else 'no'}, HttpOnly={'yes' if 'httponly' in flags else 'no'}, SameSite={'yes' if 'samesite' in flags else 'no'}")
        return "\n".join(lines)

    async def email_domain_info(self, target):
        domain = target.split("@", 1)[-1].strip().lower()
        return await self._dns_report(domain, "Email domain information")

    async def spf_check(self, target):
        return await self._txt_check(target, "SPF", lambda value: value.lower().startswith("v=spf1"))

    async def dmarc_check(self, target):
        return await self._txt_check(f"_dmarc.{target.strip()}", "DMARC", lambda value: value.lower().startswith("v=dmarc1"))

    async def _txt_check(self, target, name, predicate):
        import dns.resolver
        try:
            answers = dns.resolver.resolve(target, "TXT")
            values = ["".join(part.decode() if isinstance(part, bytes) else part for part in record.strings) for record in answers]
            matches = [value for value in values if predicate(value)]
            return "\n".join([f"[>] {name} review for {target}", f"[{'+' if matches else '-'}] Policy record: {matches[0] if matches else 'not found'}", "[+] A policy record is a starting point; enforcement strength still needs review."])
        except Exception as error:
            return f"[!] {name} could not be resolved: {type(error).__name__}"

    async def dnssec_check(self, target):
        import dns.resolver
        try:
            dns.resolver.resolve(target, "DNSKEY")
            return f"[+] DNSSEC DNSKEY record found for {target}. Confirm chain validation with your DNS provider."
        except Exception:
            return f"[!] DNSSEC could not be confirmed for {target}."

    async def _dns_report(self, target, title):
        import dns.resolver
        lines = [f"[>] {title}: {target}"]
        for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                values = [str(value) for value in dns.resolver.resolve(target, record_type)]
                lines.append(f"[+] {record_type}: {', '.join(values[:8])}")
            except Exception:
                lines.append(f"[!] {record_type}: unavailable")
        return "\n".join(lines)

    async def ip_info(self, target):
        host = target.strip()
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
            return "\n".join([f"[>] IP information for {host}"] + [f"[+] Resolved address: {address}" for address in addresses] + ["[!] ASN and geolocation require a configured provider for richer results."])
        except socket.gaierror:
            return f"[-] Could not resolve {host}."

    async def reverse_dns(self, target):
        try:
            hostname, _, addresses = socket.gethostbyaddr(target.strip())
            return f"[+] Reverse DNS: {target} -> {hostname}\n[+] Addresses: {', '.join(addresses)}"
        except (socket.herror, socket.gaierror):
            return f"[!] No reverse-DNS hostname was confirmed for {target}."

    async def company_profile(self, target):
        return await self._dns_report(target.strip(), "Company/domain public profile")

    async def coordinate_info(self, target):
        try:
            latitude, longitude = (float(value.strip()) for value in target.split(",", 1))
            if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                raise ValueError
            return f"[+] Coordinates accepted: latitude={latitude}, longitude={longitude}\n[!] Reverse geocoding requires an optional configured provider."
        except (ValueError, TypeError):
            return "[!] Use coordinates in the form: latitude, longitude"

    async def image_metadata(self, target):
        return self._file_metadata(target, "Image")

    async def document_metadata(self, target):
        return self._file_metadata(target, "Document")

    def _file_metadata(self, target, label):
        path = Path(target.strip())
        if not path.is_file():
            return f"[!] {label} file not found: {path}"
        stat = path.stat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return "\n".join([f"[>] {label} metadata for {path.name}", f"[+] Size: {stat.st_size} bytes", f"[+] SHA-256: {digest}", "[!] Specialized EXIF/PDF metadata requires an optional parser; no file contents were uploaded."])

    async def file_inventory(self, target):
        path = Path(target.strip())
        if not path.exists():
            return f"[!] Path not found: {path}"
        items = list(path.iterdir()) if path.is_dir() else [path]
        lines = [f"[>] File inventory: {path}"]
        lines.extend(f"[+] {item.name} ({item.stat().st_size} bytes)" for item in items[:100])
        return "\n".join(lines)

    async def uptime_check(self, target):
        url = self._url(target)
        try:
            response = await self.client.get(url, headers={"User-Agent": "Scylla-Uptime-Check/1.0"})
            return f"[+] {url} responded with HTTP {response.status_code}.\n[!] One request is not a continuous uptime guarantee."
        except Exception as error:
            return f"[-] {url} did not respond: {type(error).__name__}"

    async def article_summary(self, target):
        response = await self.client.get(self._url(target), headers={"User-Agent": "Scylla-Research/1.0"})
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", response.text)).strip()
        return f"[>] Article review for {target}\n[+] HTTP response: {response.status_code}\n[+] Extracted preview: {text[:500]}\n[!] This is extraction, not independent fact verification."

    async def place_search(self, target):
        return f"[>] Place research target: {target}\n[!] Configure an optional geocoding provider for live place results.\n[+] You can still use coordinate-info with supplied latitude/longitude."

    async def whois_lookup(self, target):
        domain = self._normalize_domain(target)
        if not domain or "." not in domain:
            return "[!] Enter a domain such as example.com; URLs and paths are accepted too."

        candidates = [domain]
        parent = self._registrable_parent(domain)
        if parent and parent != domain:
            candidates.append(parent)

        errors = []
        for candidate in candidates:
            result = await self._rdap_domain(candidate)
            if result[0]:
                lines = result[1]
                if candidate != domain:
                    lines.insert(1, f"[!] {domain} is a hosted subdomain; registration data is shown for parent domain {candidate}.")
                return "\n".join(lines)
            errors.append(f"{candidate}: {result[1]}")

        # Last resort: provide a stable public lookup URL rather than scraping
        # an HTML page whose layout can change and whose data may be stale.
        return "\n".join([
            f"[!] No registration record could be retrieved for {domain}.",
            "[>] Public web lookup fallback:",
            f"[+] https://www.whois.com/whois/{parent or domain}",
            f"[+] https://lookup.icann.org/en/lookup/{parent or domain}",
            "[!] Hosted subdomains usually do not have their own WHOIS record; check the parent domain.",
        ])

    async def _rdap_domain(self, domain):
        urls = [f"https://rdap.org/domain/{domain}"]
        try:
            bootstrap = await self.client.get("https://data.iana.org/rdap/dns.json", timeout=8)
            if bootstrap.status_code == 200:
                suffix = "." + domain.rsplit(".", 1)[-1]
                for service, registries in bootstrap.json().get("services", []):
                    if suffix in registries:
                        urls.extend(service)
                        break
        except Exception:
            pass
        last = "no registry response"
        for url in dict.fromkeys(urls):
            try:
                response = await self.client.get(url, headers={"Accept": "application/rdap+json, application/json"}, timeout=12)
                last = f"HTTP {response.status_code}"
                if response.status_code != 200:
                    continue
                data = response.json()
                lines = [
                    f"[>] Public WHOIS/RDAP lookup for {domain}",
                    f"[+] Handle: {data.get('handle', 'not published')}",
                    f"[+] Status: {', '.join(data.get('status', [])) or 'not published'}",
                ]
                for event in data.get("events", []):
                    if event.get("eventAction") in {"registration", "expiration", "last changed"}:
                        lines.append(f"[+] {event['eventAction'].title()}: {event.get('eventDate', 'not published')}")
                nameservers = [item.get("ldhName") for item in data.get("nameservers", []) if item.get("ldhName")]
                lines.extend([
                    f"[+] Nameservers: {', '.join(nameservers[:8]) or 'not published'}",
                    "[!] Privacy services and registry limits may hide registrant details.",
                ])
                return True, lines
            except Exception as error:
                if type(error).__name__ != "ReadTimeout":
                    last = type(error).__name__
        return False, last

    @staticmethod
    def _registrable_parent(domain):
        labels = [label for label in domain.split(".") if label]
        # This dependency-free approximation handles normal domains and common
        # multi-label public suffixes. The exact registry response remains the
        # authority, so the fallback is always clearly labeled.
        if len(labels) <= 2:
            return domain
        if len(labels[-1]) == 2 and labels[-2] in {"co", "com", "net", "org", "gov", "ac"}:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    @staticmethod
    def _normalize_domain(target):
        value = (target or "").strip().lower()
        value = re.sub(r"^https?://", "", value)
        value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        value = value.split(":", 1)[0].strip().rstrip(".")
        return value.removeprefix("www.")

    async def subdomain_enum(self, target):
        domain = target.strip().lower().replace("https://", "").replace("http://", "").split("/", 1)[0].lstrip("*.")
        try:
            response = await self.client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, headers={"Accept": "application/json"})
            if response.status_code != 200:
                return f"[!] crt.sh returned HTTP {response.status_code}."
            names = set()
            for item in response.json():
                for name in str(item.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name == domain or name.endswith("." + domain):
                        names.add(name)
            return "\\n".join([f"[>] Passive certificate-transparency enumeration for {domain}", f"[+] Unique names found: {len(names)}"] + [f"[+] {name}" for name in sorted(names)[:200]] + ["[!] Names may be expired or unrelated; verify ownership and liveness."])
        except Exception as error:
            return f"[!] Certificate-transparency lookup failed: {type(error).__name__}"

    async def tech_detect(self, target):
        url = self._url(target)
        try:
            response = await self.client.get(url, headers={"User-Agent": "Velt-Public-Tech-Review/1.0"})
            body = response.text.lower()
            headers = {key.lower(): value.lower() for key, value in response.headers.items()}
            signals = []
            checks = [("Cloudflare", "cf-ray" in headers or "cloudflare" in headers.get("server", "")), ("WordPress", "wp-content" in body or "wp-includes" in body), ("Next.js", "__next_data__" in body or "_next/" in body), ("React", "react" in body), ("nginx", "nginx" in headers.get("server", "")), ("Apache", "apache" in headers.get("server", ""))]
            signals.extend(name for name, present in checks if present)
            return "\\n".join([f"[>] Passive technology detection for {url}", f"[+] HTTP response: {response.status_code}", f"[+] Signals: {', '.join(signals) if signals else 'none confidently detected'}", "[!] Fingerprinting is heuristic and may be hidden or spoofed."])
        except Exception as error:
            return f"[!] Technology detection failed: {type(error).__name__}"

    async def certificate_history(self, target):
        return await self.subdomain_enum(target)

    async def asn_details(self, target):
        host = target.strip()
        try:
            address = socket.gethostbyname(host)
            response = await self.client.get(f"https://ipwho.is/{address}")
            data = response.json()
            connection = data.get("connection", {})
            return "\\n".join([f"[>] Public network ownership for {host} ({address})", f"[+] ISP: {connection.get('isp', 'not published')}", f"[+] Organization: {connection.get('org', 'not published')}", f"[+] ASN: {connection.get('asn', 'not published')}", "[!] Ownership and geolocation data may be approximate."])
        except Exception as error:
            return f"[!] ASN lookup failed: {type(error).__name__}"

    async def email_discovery(self, target):
        response = await self.client.get(self._url(target), headers={"User-Agent": "Velt-Public-Contact-Audit/1.0"})
        emails = sorted(set(re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}", response.text, re.I)))
        return "\\n".join([f"[>] Public email clues from {target}", f"[+] Addresses found: {len(emails)}"] + [f"[+] {email}" for email in emails[:50]] + ["[!] Only one public page was checked; do not use this for bulk harvesting."])

    async def port_services(self, target):
        import asyncio as _asyncio
        host = target.strip()
        ports = {80: "HTTP", 443: "HTTPS", 22: "SSH", 25: "SMTP", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-alt"}
        async def check(port, label):
            try:
                reader, writer = await _asyncio.wait_for(_asyncio.open_connection(host, port), timeout=1.5)
                writer.close()
                await writer.wait_closed()
                return f"[!] Port {port} ({label}): Open — review whether it must be public"
            except Exception:
                return f"[+] Port {port} ({label}): Not reachable from this check"
        results = await _asyncio.gather(*(check(port, label) for port, label in ports.items()))
        return "\\n".join([f"[>] Small authorized TCP service review for {host}", *results, "[!] Only scan systems you own or are explicitly authorized to assess."])

    async def threat_feed_check(self, target):
        value = target.strip()
        if value.startswith("http://") or value.startswith("https://"):
            try:
                response = await self.client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": value})
                data = response.json()
                if data.get("query_status") == "no_results":
                    return f"[+] URLhaus: no matching malware URL report for {value}.\\n[!] A clean feed result is not proof of safety."
                return f"[-] URLhaus: matching report found for {value}.\\n[!] Investigate and contain only with proper authorization."
            except Exception as error:
                return f"[!] URLhaus lookup failed: {type(error).__name__}"
        try:
            address = socket.gethostbyname(value)
            key = getattr(self, "config", None)
            return f"[>] Threat-feed context for {value} ({address})\\n[!] AbuseIPDB requires an API key; configure it in Velt settings before querying IP reputation.\\n[!] No reputation claim was fabricated."
        except Exception:
            return "[!] Provide a valid public URL or hostname/IP address."

    async def provider_placeholder(self, target):
        return "\n".join([
            f"[>] Public research target: {target}",
            "[!] This check needs an optional provider or a more specific local data source.",
            "[+] No external lookup was fabricated; configure a provider in SETTINGS / API KEYS when available.",
        ])

    async def cloud_service_map(self, target):
        return "\n".join([
            f"[>] Passive cloud-service clues for {target}",
            "[!] Cloud ownership cannot be proven from one DNS response.",
            "[+] Review DNS, response headers, and your cloud inventory together.",
        ])

    async def origin_review(self, target):
        response = await self.client.get(self._url(target), headers={"User-Agent": "Scylla-Origin-Review/1.0"})
        headers = {key.lower(): value for key, value in response.headers.items()}
        edge = any(key in headers for key in ("cf-ray", "x-cache", "x-amz-cf-id", "x-sucuri-id"))
        return "\n".join([
            f"[>] Passive origin review for {target}",
            f"[{'+' if edge else '!'}] Edge/CDN signal: {'observed' if edge else 'not observable'}",
            "[!] A public response cannot prove that the origin IP is private; verify this in the CDN and DNS dashboards.",
        ])

    async def public_links(self, target):
        response = await self.client.get(self._url(target), headers={"User-Agent": "Scylla-Public-Links/1.0"})
        links = re.findall(r"href=[\\\"']([^\\\"'#]+)", response.text, re.I)
        return "\n".join([f"[>] Public links from {target}", f"[+] Links found: {len(links)}"] + [f"[+] {link}" for link in links[:50]])

    async def local_timeline(self, target):
        path = Path(target.strip())
        if not path.is_file():
            return f"[!] Local research file not found: {path}"
        lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        return "\n".join([f"[>] Local research notes: {path}", f"[+] Notes loaded: {len(lines)}"] + [f"[+] {line}" for line in lines[:100]])

    async def local_file_guidance(self, target):
        path = Path(target.strip())
        return "\n".join([
            f"[>] Local file review target: {path}",
            f"[{'+' if path.exists() else '!'}] Path: {'found' if path.exists() else 'not found'}",
            "[!] Specialized parsing is not enabled; no file was uploaded.",
        ])

    async def secret_scan(self, target):
        path = Path(target.strip())
        if not path.is_file():
            return f"[!] Local file not found: {path}"
        patterns = re.compile(r"(?i)(api[_-]?key|secret|token|password)\\s*[:=]")
        matches = [index for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1) if patterns.search(line)]
        return "\n".join([
            f"[>] Redacted local secret-pattern review: {path}",
            f"[{'-' if matches else '+'}] Candidate secret-shaped lines: {len(matches)}",
            "[!] Values are never printed. Review and rotate any real credentials manually.",
        ])
