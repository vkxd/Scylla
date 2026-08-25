```text
   ____                    _ _           ____   _____ _____ _   _ _____
  / ___|  ___ _   _  ___  | | | __ _    / ___| | ____|_   _| | | | ____|
  \___ \ / __| | | |/ _ \ | | |/ _` |   \___ \ |  _|   | | | | | |  _|
   ___) | (__| |_| |  __/ | | | (_| |    ___) || |___  | | | |_| | |___
  |____/ \___|\__,_|\___| |_|_|\__,_|   |____/ |_____| |_|  \___/|_____|
```

# Scylla

[![OSINT](https://img.shields.io/badge/Focus-OSINT-4B0082?style=for-the-badge)](https://en.wikipedia.org/wiki/Open-source_intelligence)
[![Defensive Security](https://img.shields.io/badge/Focus-Defensive%20Security-1F6FEB?style=for-the-badge)](https://www.nist.gov/cyberframework)
[![Terminal](https://img.shields.io/badge/Interface-Terminal-111111?style=for-the-badge)](https://en.wikipedia.org/wiki/Computer_terminal)
[![Authorized Research](https://img.shields.io/badge/Use-Authorized%20Research-2EA44F?style=for-the-badge)](https://github.com/vkxd/Scyll)

Scylla is a terminal-based OSINT and defensive security research tool. It helps you investigate public information, review websites you own or are authorized to test, and organize findings in one interface.

> Use Scylla as a research and configuration-guidance tool. Results may be incomplete, blocked, uncertain, or require manual verification.

## How the UI Works

Scylla organizes tools into categories:

1. Categories appear in the left sidebar.
2. Select a category.
3. The category's tools appear on the right.
4. Select a tool.
5. Use the tool-specific CLI.
6. Run `help` to learn what the tool does.

### Example

~~~text
Click vulnerability
Click security-headers
/help
set target https://example.com
run
~~~

## Main Categories

| Category | Description |
|---|---|
| Vulnerability | Ports, DDoS resilience, subdomains, technology stacks, CVEs, headers, cookies, SSL/TLS, secrets, and more. |
| DNS | DNS records, SPF, DMARC, DNSSEC, reverse DNS, ASN, and certificate clues. |
| Web Security | Website information, uptime, redirects, and public-page extraction. |
| Social | Sherlock-style username searches across public platforms. |
| Email | Email-domain security and header analysis. |
| IP Intelligence | IP resolution, reverse DNS, and network context. |
| Cloud | Storage, CDN, origin, and cloud-service reviews. |
| People | Organization of public profiles and public links. |
| News | Article research, source comparison, and timelines. |
| Business | Company profiles, brands, and product research. |
| Geospatial | Coordinate validation and public place research. |
| Images | Local metadata, hashes, metadata-cleaning guidance, and OCR planning. |
| Documents | Local metadata, text extraction, and file inventory. |
| Monitoring | Uptime, certificate expiry, and exposure comparisons. |
| Breaches | Breach-source guidance and authorized local password-policy analysis. |
| Temporary Mail | Disposable mailbox utility. |

## Important Tools

### Username Checker

The username checker searches public profile URLs across approximately 30 platforms.

~~~text
/help
set username itskingkad
run
~~~

Possible results include:

~~~text
[+] Possible profile found
[-] Not found
[!] Blocked, rate-limited, timed out, or uncertain
~~~

A possible match is only a lead. It does not prove that every account belongs to the same person.

### DDoS Resilience Assessment

The DDoS resilience assessment does **not** perform a DDoS attack. It makes a safe, limited HTTP inspection and looks for indicators such as:

- CDN or WAF protection.
- Rate limiting.
- Caching.
- HSTS.
- Origin-shielding indicators.
- Large responses.
- Possible protection gaps.

~~~text
/help
set target https://yourwebsite.com
run
~~~

The tool explains which protections appear effective and what should be configured or verified manually.

### Security Headers

The security-header tool checks browser protection headers, including:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `X-Content-Type-Options`

~~~text
set target https://example.com
run
~~~

### CVE Matching

CVE stands for **Common Vulnerabilities and Exposures**. CVEs are public records describing known software vulnerabilities.

The CVE tool helps identify which updates may deserve attention. A match is not automatically proof that a system is exploitable.

### DNS and Email Checks

DNS and email checks help explain how a domain is configured.

~~~text
set target example.com
run
~~~

These checks can review:

- A records.
- AAAA records.
- MX records.
- SPF.
- DMARC.
- DNSSEC.
- Nameservers.
- Reverse DNS.

## Common Commands

~~~text
help
set target https://example.com
set username itskingkad
run
clear
back
export json
export csv
export md
~~~

Generated reports are saved in:

~~~text
outputs/
~~~

## Status Colors

| Indicator | Meaning |
|---|---|
| `[+]` Green | Positive result, item found, or protection observed. |
| `[-]` Red | Negative result or possible issue. |
| `[!]` Yellow | Warning, uncertainty, blocked request, or unverified result. |

## Settings

The Settings screen supports optional API keys for providers such as:

- Shodan.
- Have I Been Pwned.
- GitHub.
- Search providers.
- Geocoding providers.
- NVD/CVE data providers.

Keys are masked and stored locally. Tools that require a provider should identify that requirement instead of generating unsupported results.

## Current Limitations

Scylla intentionally does not:

- Perform DDoS attacks or flooding.
- Exploit vulnerabilities.
- Test passwords against accounts.
- Bypass CAPTCHAs or rate limits.
- Access private profiles.
- Track people in real time.
- Prove that two public accounts belong to the same person.

Some advanced tools currently provide safe local analysis or explain which optional provider is required.

## Responsible Use

Only use Scylla for lawful and authorized research.

You should only inspect:

- Public information.
- Websites and systems you own.
- Websites and systems for which you have explicit authorization to test.
- Local files and data you are permitted to analyze.

Do not use Scylla to harass, stalk, target, or gain unauthorized access to individuals, organizations, accounts, or systems.

## Interpreting Results

Scylla results should be treated as research leads and configuration guidance, not absolute proof.

A result may be affected by:

- Rate limiting.
- Blocked requests.
- Network errors.
- Missing API keys.
- Incomplete public information.
- False positives.
- Service changes.
- Unavailable providers.

Always verify important findings manually and use multiple reliable sources when appropriate.

## Repository

[![GitHub Repository](https://img.shields.io/badge/GitHub-vkxd%2FScyll-181717?style=for-the-badge&logo=github)](https://github.com/vkxd/Scyll)

[Visit the Scylla repository](https://github.com/vkxd/Scyll)
