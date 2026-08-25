# Scylla OSINT

Scylla is a beginner-friendly terminal OSINT workspace for public-information research and authorized defensive security review.

## Quick start

```bash
pip install -r requirements.txt
python main.py
```

The UI flow is:

1. Select a category.
2. Select a tool.
3. Run `help` to see what it does, why it matters, its limits, and its required inputs.
4. Set the tool's input and run it.

Example:

```text
Select vulnerability
Select ddos-assessment
/help
set target https://example.com
run
export json
```

Supported commands inside every tool:

```text
help                 Show beginner-friendly tool guidance
set <field> <value>  Provide the selected tool's input
run                  Execute the tool
export json|csv|md   Save the current output under outputs/
clear                Clear the tool log
back                 Return to the tool list
```

The title also displays: `run "help" in any tool to see what it actually does`.

## Catalog

The catalog includes 16 categories and 60 tools across vulnerability review, DNS, web security, social usernames, email, IP context, cloud, people, news, business, geospatial, images, documents, monitoring, breaches, and temporary mail.

The username checker performs bounded, Sherlock-style public URL checks across a larger platform list. It reports found, not found, blocked/rate-limited, timeout, and unknown states. It does not bypass CAPTCHAs, log in, or evade rate limits.

Many general OSINT tools are deliberately local or provider-aware. When a live source is not configured, Scylla says so instead of inventing a result.

## Optional provider configuration

Use **SETTINGS / API KEYS** in the UI, or create a local `.env` from `.env.example`. You may also copy `config.example.json` to `config.json`.

- `.env` and `config.json` are ignored by Git.
- Keys are masked in the settings screen.
- Reports redact common credential-shaped values.
- Never put real keys in source files or commit them.

## Safety

Use Scylla only for public information, files you own, and systems you are authorized to assess. It does not perform credential testing, exploitation, CAPTCHA bypass, private-account access, flooding, stress attacks, or DDoS attacks. The DDoS tool is an evidence-based, low-volume resilience review and clearly labels checks that cannot be proven safely.

Username and people-research results are leads, not identity proof. Respect platform terms, privacy, consent, and applicable law.
