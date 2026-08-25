from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass(frozen=True)
class ToolSpec:
    key: str
    name: str
    description: str
    module_id: str
    fields: List[Tuple[str, str, str]] = field(default_factory=list)
    what_it_does: str = "Runs a public-information check for the selected target."
    why_it_matters: str = "It helps you understand what is exposed and what should be reviewed."
    limitations: str = "Results are limited to safe checks and configured sources."
    risk: str = "low"


@dataclass(frozen=True)
class CategorySpec:
    key: str
    name: str
    description: str
    tools: List[ToolSpec]


def t(key, name, description, module_id, fields, what, why, limitations="Results are limited to safe checks and configured sources.", risk="low"):
    return ToolSpec(key, name, description, module_id, fields, what, why, limitations, risk)


TARGET = [("target", "Target", "example.com")]
URL = [("target", "Website URL", "https://example.com")]
FILE = [("target", "Local file or folder", "./file.txt")]
USERNAME = [("username", "Username", "itskingkad")]

CATEGORIES = [
    CategorySpec("vulnerability", "VULNERABILITY", "Authorized website and infrastructure security review.", [
        t("ports", "Open Ports", "Review responding network services.", "sub_ports", TARGET, "Checks which network doors (ports) respond on a host.", "Open ports reveal reachable services; closing unnecessary ones reduces attack surface.", risk="medium"),
        t("ddos-assessment", "DDoS Resilience Assessment", "Find public signs of traffic protection without attacking.", "sub_ddos_assessment", URL, "Looks for CDN/WAF, rate limiting, caching, and other resilience signals.", "DDoS means distributed denial of service; this helps website owners find protection gaps.", risk="medium"),
        t("subdomains", "Subdomains / Pages", "Find public subdomain and path clues.", "sub_subdomains", TARGET, "Finds related names such as dev.example.com and public website locations.", "Forgotten test sites and admin pages can expose software or login panels.", risk="medium"),
        t("tech", "Tech Stack", "Identify public server, framework, CMS, and TLS clues.", "sub_tech", URL, "Identifies public clues about software used by a website.", "Knowing the technology helps you patch old versions and configure defenses."),
        t("cves", "CVE Matching", "Explain known software vulnerability records.", "sub_cves", TARGET, "Matches software versions to CVEs, public records of specific vulnerabilities.", "CVE matches show which patches should be prioritized; they are leads to verify, not proof of compromise."),
        t("buckets", "Cloud Buckets", "Review possible public cloud-storage exposure.", "sub_buckets", TARGET, "Looks for public cloud-storage naming patterns.", "A misconfigured bucket can expose files, backups, or customer data.", risk="medium"),
        t("security-headers", "Security Headers", "Check browser security headers.", "security_headers", URL, "Checks CSP, HSTS, framing, referrer, and browser-protection headers.", "Headers tell browsers which defensive rules to enforce."),
        t("ssl-check", "SSL / TLS Check", "Review HTTPS hardening clues.", "ssl_check", URL, "Checks whether HTTPS and HSTS are observable.", "Transport protection helps prevent interception."),
        t("redirect-checker", "Redirect Checker", "Inspect the first public redirect.", "redirect_checker", URL, "Shows whether a URL redirects and where it points.", "Unexpected cross-domain redirects can indicate misconfiguration or phishing risk."),
        t("cookie-audit", "Cookie Audit", "Review cookie security flags.", "cookie_audit", URL, "Checks Secure, HttpOnly, and SameSite flags.", "Secure cookie flags reduce accidental session-data exposure."),
        t("robots-analyzer", "Robots Analyzer", "Explain a public robots.txt file.", "robots_analyzer", URL, "Reads crawler instructions published at robots.txt.", "It helps owners understand public crawler guidance; it is not access control."),
        t("sitemap-analyzer", "Sitemap Analyzer", "Review public sitemap entries.", "sitemap_analyzer", URL, "Reads public sitemap.xml URLs.", "Sitemaps show what a site advertises to search engines."),
        t("dependency-audit", "Dependency Audit", "Plan authorized package-version review.", "dependency_audit", FILE, "Reviews local package files when an advisory provider is configured.", "Outdated dependencies may contain known vulnerabilities.", risk="medium"),
        t("secret-scan", "Secret Scan", "Find likely secrets in authorized local files.", "secret_scan", FILE, "Looks for secret-shaped text locally and redacts matches.", "It helps owners remove accidentally exposed tokens.", risk="high"),
    ]),
    CategorySpec("dns", "DNS", "Internet address-book and email-domain research.", [
        t("infra-map", "Infrastructure Map", "Map public DNS clues.", "infra_map", TARGET, "Maps public DNS records and infrastructure clues.", "DNS can reveal related hosts that should be protected."),
        t("records", "DNS Records", "List common DNS records.", "infra_map", TARGET, "Lists A, AAAA, MX, NS, and TXT records.", "Records explain where a domain sends web traffic and email."),
        t("spf-check", "SPF Check", "Review email sender authorization.", "spf_check", TARGET, "Checks whether a domain publishes an SPF policy.", "SPF can reduce forged messages sent as a domain."),
        t("dmarc-check", "DMARC Check", "Review anti-spoofing email policy.", "dmarc_check", TARGET, "Checks whether a domain publishes a DMARC policy.", "DMARC tells mail providers what to do when authentication fails."),
        t("dnssec-check", "DNSSEC Check", "Check DNSSEC clues.", "dnssec_check", TARGET, "Looks for DNSSEC DNSKEY records.", "DNSSEC helps validate DNS answers."),
        t("reverse-dns", "Reverse DNS", "Find a public hostname for an IP.", "reverse_dns", TARGET, "Looks up the PTR hostname associated with an IP.", "It adds infrastructure context."),
        t("certificate-search", "Certificate Search", "Explain certificate-transparency discovery.", "certificate_search", TARGET, "Explains optional certificate provider requirements.", "Certificates can reveal hostnames owners forgot to track."),
        t("asn-map", "ASN Map", "Explain network ownership lookup.", "asn_map", TARGET, "Prepares an organization or IP for an optional ASN provider.", "ASN context shows which organization operates a network."),
    ]),
    CategorySpec("web", "WEB SECURITY", "Website, hosting, and public web research.", [
        t("info", "Website Information", "Build a basic domain overview.", "web_info", TARGET, "Collects public DNS and hosting clues.", "It gives beginners a starting map of how a website connects to the internet."),
        t("uptime-check", "Uptime Check", "Make one safe availability request.", "uptime_check", URL, "Checks whether a website responds once.", "It provides a snapshot, not a continuous uptime guarantee."),
        t("article-summary", "Article Summary", "Extract a preview from a public URL.", "article_summary", URL, "Extracts a short text preview from a public page.", "It helps organize research while separating extraction from fact verification."),
    ]),
    CategorySpec("social", "SOCIAL", "Public username and profile research.", [
        t("username-checker", "Sherlock-Style Username Search", "Check a large public platform catalog.", "sub_sherlock", USERNAME, "Searches public profile URLs with found, not-found, blocked, and unknown states.", "It shows where a public alias may be reused; results do not prove profiles belong to one person.", "Platforms may block automated checks or change their pages.", "medium"),
        t("alias-search", "Alias Search", "Search a public alias across platforms.", "alias_search", USERNAME, "Runs the same conservative public alias search.", "It helps organize a public online presence review.", risk="medium"),
    ]),
    CategorySpec("email", "EMAIL", "Email-domain security and header research.", [
        t("domain-info", "Email Domain Info", "Review email-domain DNS records.", "email_domain_info", [("target", "Email or domain", "user@example.com")], "Lists DNS records supporting email delivery.", "It shows whether a domain has basic trustworthy-mail infrastructure."),
        t("spf-check", "SPF Check", "Review sender authorization.", "spf_check", TARGET, "Checks an SPF record.", "It can reduce spoofed messages."),
        t("dmarc-check", "DMARC Check", "Review spoofing policy.", "dmarc_check", TARGET, "Checks a DMARC record and policy.", "It helps owners strengthen anti-spoofing enforcement."),
        t("header-analyzer", "Email Header Analyzer", "Plan local header parsing.", "header_analyzer", FILE, "Explains local email-header parsing without uploading the message.", "Headers can reveal authentication results and delivery hops.", "Never paste passwords or private message content."),
    ]),
    CategorySpec("ip", "IP INTELLIGENCE", "Public address, DNS, and network context.", [
        t("ip-info", "IP Information", "Resolve public host addresses.", "ip_info", TARGET, "Resolves a hostname to public IP addresses.", "It helps identify a website's network location; geolocation is approximate."),
        t("reverse-dns", "Reverse DNS", "Find public PTR hostnames.", "reverse_dns", TARGET, "Looks for a hostname associated with an IP.", "It adds infrastructure context."),
        t("network-range", "Network Range", "Explain optional ASN lookup.", "network_range", TARGET, "Prepares an address or organization for a configured provider.", "Network ranges help owners inventory public assets."),
    ]),
    CategorySpec("cloud", "CLOUD", "Authorized cloud-service and storage review.", [
        t("storage-review", "Storage Review", "Plan authorized public-storage checks.", "storage_review", TARGET, "Explains a safe cloud-storage review workflow.", "Misconfigured public storage can expose backups or documents.", "Only use on storage you own or are authorized to audit.", "medium"),
        t("cloud-service-map", "Cloud Service Map", "Identify public cloud clues.", "cloud_service_map", TARGET, "Organizes DNS and header clues for cloud services.", "It helps owners understand which cloud edges are public."),
        t("origin-review", "Origin Review", "Review CDN/origin indicators.", "origin_review", URL, "Explains passive origin-exposure indicators.", "Keeping an origin private helps traffic controls work.", risk="medium"),
    ]),
    CategorySpec("people", "PEOPLE", "Public-profile organization, not private-person surveillance.", [
        t("profile-summary", "Profile Summary", "Organize a supplied public profile.", "profile_summary", URL, "Summarizes public profile text and links.", "It turns scattered public information into a cited starting point.", "Public sources only; no private-account access."),
        t("public-links", "Public Links", "Collect links from a public page.", "public_links", URL, "Extracts links from a supplied public page.", "It helps map a public creator, project, or organization."),
        t("timeline", "Timeline Notes", "Organize user-supplied dated notes.", "timeline_notes", FILE, "Reads a local authorized text file and organizes dated lines.", "A timeline makes research easier to verify.", "It does not infer private facts."),
    ]),
    CategorySpec("news", "NEWS", "Source comparison and public media research.", [
        t("article-search", "Article Search", "Plan configured news/RSS search.", "article_search", TARGET, "Searches configured public news providers.", "It helps discover multiple sources for an event.", "Requires a configured provider for live search."),
        t("source-compare", "Source Compare", "Compare supplied public articles.", "source_compare", FILE, "Organizes supplied article excerpts or URLs.", "Comparing sources separates common facts from disputed claims."),
        t("timeline-builder", "News Timeline", "Build a timeline from local notes.", "timeline_builder", FILE, "Orders dated lines in a local research file.", "Chronology helps reveal what happened and when."),
    ]),
    CategorySpec("business", "BUSINESS", "Public company, product, and brand research.", [
        t("company-profile", "Company Profile", "Build a public domain overview.", "company_profile", TARGET, "Combines public DNS context with a company target.", "It creates a starting point for vendor and product research."),
        t("brand-monitor", "Brand Monitor", "Plan public lookalike-domain review.", "brand_monitor", TARGET, "Explains optional domain-provider checks.", "Lookalike domains can be used for phishing or brand confusion."),
        t("product-research", "Product Research", "Extract a public product-page preview.", "article_summary", URL, "Extracts public text from a supplied product page.", "It helps compare public product claims."),
    ]),
    CategorySpec("geospatial", "GEOSPATIAL", "Public map context and user-supplied coordinates.", [
        t("coordinate-info", "Coordinate Info", "Validate latitude and longitude.", "coordinate_info", [("target", "Coordinates", "40.7128, -74.0060")], "Validates user-supplied coordinates.", "It prevents coordinate-format mistakes.", "No real-time tracking or private-address discovery."),
        t("place-search", "Place Search", "Plan optional public map search.", "place_search", [("target", "Place or landmark", "Central Park")], "Explains optional provider requirements for live place search.", "It helps organize public place research without tracking people."),
    ]),
    CategorySpec("images", "IMAGES", "Local image metadata and visual research helpers.", [
        t("metadata", "Image Metadata", "Read local file size and hash.", "image_metadata", FILE, "Reads local image file information without uploading it.", "Metadata and hashes help verify files and identify privacy risks.", "Specialized EXIF parsing is provider-dependent."),
        t("metadata-cleaner", "Metadata Cleaner", "Plan local metadata removal.", "metadata_cleaner", FILE, "Explains how to create a sanitized local copy.", "Removing GPS and device metadata can protect privacy.", "Keep an original backup."),
        t("ocr", "Image Text Notes", "Plan local OCR extraction.", "ocr", FILE, "Explains local text extraction from authorized images.", "Visible text can provide research clues.", "OCR can make mistakes."),
    ]),
    CategorySpec("documents", "DOCUMENTS", "Local document inventory and metadata research.", [
        t("metadata", "Document Metadata", "Read local file size and hash.", "document_metadata", FILE, "Reads local document information without uploading it.", "Hashes help verify files and metadata reviews can reveal privacy leaks."),
        t("text-extract", "Text Extract", "Plan local text extraction.", "text_extract", FILE, "Explains local extraction from authorized documents.", "Extracted text is easier to search and cite."),
        t("file-inventory", "File Inventory", "List local files and sizes.", "file_inventory", FILE, "Lists files in a local folder or file path.", "Inventory helps understand an evidence set before analyzing it.", "Only inspect files you are authorized to access."),
    ]),
    CategorySpec("monitoring", "MONITORING", "Safe user-triggered availability and change checks.", [
        t("uptime-check", "Uptime Check", "Make one normal availability request.", "uptime_check", URL, "Checks whether a site responds once.", "It gives a snapshot without pretending to be continuous monitoring."),
        t("certificate-expiry", "Certificate Expiry", "Plan certificate monitoring.", "certificate_expiry", URL, "Explains optional certificate monitoring.", "Expiry alerts prevent avoidable HTTPS outages."),
        t("exposure-diff", "Exposure Diff", "Plan comparison of saved reports.", "exposure_diff", FILE, "Explains comparing two saved local reports.", "A diff highlights new public exposure."),
    ]),
    CategorySpec("breaches", "BREACHES", "Breach awareness and authorized local analysis.", [
        t("lookup", "Breach Lookup", "Check configured breach-intelligence sources.", "breach_lookup", [("target", "Email or username", "analyst@example.com")], "Checks configured sources for breach reports.", "It helps decide whether to change passwords and enable MFA; never enter secrets.", risk="medium"),
        t("predict-creds", "Credential Analyzer", "Profile an authorized local text dataset.", "analyze_passwords", FILE, "Reviews an authorized local text dataset for password patterns.", "It helps owners identify risky reuse and improve password policy.", "Never use results to attempt logins.", "high"),
    ]),
    CategorySpec("temps", "TEMPS", "Disposable mailbox utilities.", [
        t("tempmail", "Temporary Mail", "Generate a disposable inbox.", "run_all", [("provider", "Provider", "fake.legal")], "Creates a temporary mailbox using fake.legal, anonbox, or maildrop.", "It can reduce spam for low-trust signups; never use it for important accounts.", "Provider availability varies; fake.legal is fastest.", "low"),
        t("tempmail-check", "Check Inbox", "Check a temp inbox for new emails.", "check_inbox", [("email", "Email address", "user@fake.legal")], "Retrieves messages from a generated temporary inbox.", "Useful for receiving verification codes without exposing your real email.", "Only works with inboxes you just created.", "low"),
    ]),
]
