# Scylla Expansion Plan

## Implemented foundation

Scylla is expanding from a cybersecurity-focused scanner into a beginner-friendly OSINT workspace. The application now has a catalog model for cyber and general research categories, tool-specific help metadata, optional provider configuration, local report exports, and bounded public username checks.

## Categories

### Cyber and infrastructure

- `vulnerability/`: ports, DDoS resilience assessment, subdomains, tech stack, CVEs, cloud buckets, security headers, SSL/TLS, redirects, cookies, robots, sitemaps, dependencies, and secret scanning.
- `dns/`: infrastructure map, records, SPF, DMARC, DNSSEC, reverse DNS, certificate search, and ASN context.
- `email/`: domain information, SPF, DMARC, and local header analysis.
- `ip/`: IP resolution, reverse DNS, and network-range context.
- `cloud/`: storage, cloud-service, and origin-review guidance.
- `breaches/`: configured breach lookup and authorized local credential-data profiling.
- `monitoring/`: uptime and future baseline/diff checks.

### General OSINT

- `people/`: public profile summaries, public links, and user-supplied timelines.
- `news/`: article search/provider guidance, source comparison, and timelines.
- `business/`: company profiles, brand monitoring guidance, and product research.
- `geospatial/`: coordinate validation and optional place search.
- `images/`: local metadata, metadata-cleaning guidance, and OCR guidance.
- `documents/`: local metadata, text extraction guidance, and file inventory.
- `web/`: website information, uptime, and public article extraction.
- `social/`: Sherlock-style public username reconnaissance.
- `temps/`: disposable inbox utility.

## Beginner help

Every tool supports `help` and `/help`, showing:

- What it does.
- Why it matters.
- Limitations.
- Risk level.
- Required input commands.

The main UI displays: `run "help" in any tool to see what it actually does`.

## Secure API-key settings

Users may enter their own optional provider keys from `SETTINGS / API KEYS`. Keys are masked in the UI and saved only to local `config.json` when the user clicks save. Environment variables in a local `.env` take precedence for provider keys.

Never commit `.env` or `config.json`. Use `.env.example` and `config.example.json` as templates. Generated `outputs/` reports and Python caches are ignored as well.

Supported provider names currently include:

- Shodan.
- Have I Been Pwned.
- GitHub.
- Search provider.
- Geocoding provider.
- NVD.

Providers that are not configured must report that clearly instead of fabricating results.

## Username reconnaissance

The username checker uses a larger platform catalog with bounded concurrency, platform-specific URL templates, redirect/body checks, retry behavior, and separate states for found, not found, blocked/rate-limited, timeout, and unknown. It does not bypass CAPTCHAs, authentication, or rate limits.

## Safety boundaries

Scylla is for public information and authorized local/security review only. It must not perform credential testing, exploitation, flooding, stress attacks, CAPTCHA bypass, private-account access, stalking, doxxing, or sensitive-person inference. DDoS assessment remains a defensive HTTP review and never launches MHDDoS or similar traffic.

## Current implementation status

The first expansion pass is implemented:

- The 16-category, 60-tool catalog is live in the category-to-tool-to-CLI workflow.
- Every tool has beginner help metadata and a clear limitations/risk description.
- Safe local helpers, DNS/web checks, public-link extraction, coordinate validation, and provider-aware placeholders are wired through the engine.
- Reports can be exported as JSON, CSV, or Markdown with common secret-shaped values redacted.
- Tool execution shows a live `.`, `..`, `...` waiting animation and stops it on completion or failure.
- Settings, local provider keys, environment precedence, masked display, and ignored secret files are implemented.

## Follow-up hardening

1. Add provider-specific API clients one at a time with mocked transports.
2. Add structured finding/source/evidence objects while preserving the readable CLI output.
3. Add cancellation and saved-report comparison to the CLI.
4. Add local EXIF, PDF, Office, OCR, and package-manifest parsers only where dependencies are explicitly approved.
5. Add baseline comparison and watchlist storage with explicit user-triggered execution.
