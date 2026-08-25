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
