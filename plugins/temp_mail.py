import random
import string

from .base import BasePlugin


class TempMail(BasePlugin):
    """Disposable mailbox generator supporting multiple providers."""

    PROVIDERS = ["fake.legal", "mail.tm", "maildrop"]
    values = {}  # Will be set by engine before run_all

    async def run_all(self, target=None):
        # Handle run modes: "provider" or "check"
        if target == "provider":
            return await self._create_inbox()
        elif target == "check":
            return await self._check_inbox_from_values()
        
        # Default: create inbox with the specified provider
        return await self._create_inbox()

    # Map common input variations to canonical provider names
    PROVIDER_ALIASES = {
        "fake.legal": "fake.legal",
        "fakelegal": "fake.legal",
        "mail.tm": "mail.tm",
        "mailtm": "mail.tm",
        "maildrop": "maildrop",
        "maildrop.cc": "maildrop",
    }

    async def _create_inbox(self):
        """Create a new inbox using the selected provider."""
        provider_input = (self.values.get("provider", "") if hasattr(self, "values") else "") or "fake.legal"
        provider_input = provider_input.strip().lower()

        # Resolve aliases
        provider = self.PROVIDER_ALIASES.get(provider_input, provider_input)

        if provider not in self.PROVIDERS:
            return (
                f"[!] Unknown provider: {provider_input}\n"
                f"[>] Available providers: {', '.join(self.PROVIDERS)}\n"
                f"[>] Usage: set provider fake.legal"
            )

        if provider == "fake.legal":
            return await self._create_fake_legal()
        if provider == "mail.tm":
            return await self._create_mailtm()
        if provider == "maildrop":
            return await self._create_maildrop()
        return f"[!] Provider '{provider}' is not implemented yet."

    async def _check_inbox_from_values(self):
        """Check an inbox using the check field value."""
        check_email = self.values.get("check", "") if hasattr(self, "values") else ""
        if not check_email:
            return "[!] No email set to check.\n[>] Usage: set check <email> then run check"
        return await self._check_inbox(check_email)

    async def run_sub(self, sub_id, target):
        if sub_id == "check_inbox":
            return await self._check_inbox(target)
        return await self.run_all(target)

    # ── fake.legal (HTTP API — no Selenium needed) ──────────────────────

    async def _create_fake_legal(self):
        try:
            resp = await self.client.get("https://fake.legal/api/inbox/new")
            data = resp.json()
            if data.get("success"):
                address = data["address"]
                expires = data.get("expiresIn", "unknown")
                report = (
                    "[+] fake.legal inbox created\n"
                    f"[+] Email: {address}\n"
                    f"[+] Expires in: {expires}\n"
                    "\n"
                    "To check for emails:\n"
                    f"  set check {address}\n"
                    "  run\n"
                    "\n"
                    "Or visit: https://fake.legal"
                )
                return report
            return "[-] fake.legal API returned an error. Try another provider."
        except Exception as e:
            return f"[-] fake.legal request failed: {type(e).__name__}: {e}"

    async def _check_inbox(self, email):
        if not email:
            return "[!] Usage: set check <email> then run"

        # fake.legal check
        if "fake.legal" in email:
            return await self._check_fake_legal_inbox(email)

        # maildrop — no API, guide user to website
        if "maildrop.cc" in email:
            return (
                f"[+] maildrop inbox: {email}\n"
                "[>] Visit https://maildrop.cc/inbox/?mailbox=<username> to check messages.\n"
                "[>] Replace <username> with the part before @maildrop.cc"
            )

        # mail.tm — guide user to website (requires auth)
        return (
            f"[!] mail.tm inbox: {email}\n"
            "[>] mail.tm requires login to check emails.\n"
            "[>] Visit https://mail.tm and sign in with your email.\n"
            "[>] Use the password shown when you created the inbox."
        )

    async def _check_fake_legal_inbox(self, email):
        try:
            resp = await self.client.get(f"https://fake.legal/api/inbox/{email}")
            data = resp.json()
            if not data.get("success"):
                return "[-] Could not retrieve inbox. Check the email address."
            emails = data.get("emails", [])
            if not emails:
                return f"[!] No emails yet for {email}\n[>] Wait a moment and try again."
            lines = [f"[+] Found {len(emails)} email(s) for {email}:\n"]
            for i, msg in enumerate(emails, 1):
                lines.append(f"  {i}. From: {msg.get('from', 'unknown')}")
                lines.append(f"     Subject: {msg.get('subject', 'no subject')}")
                lines.append(f"     Date: {msg.get('date', 'unknown')}")
                lines.append(f"     ID: {msg.get('id', 'unknown')}")
            lines.append("\n[>] To read an email, note its ID and visit fake.legal")
            return "\n".join(lines)
        except Exception as e:
            return f"[-] Inbox check failed: {type(e).__name__}: {e}"

    # ── mail.tm (HTTP API — no Selenium needed) ─────────────────────────

    async def _create_mailtm(self):
        try:
            # Step 1: Get available domains
            resp = await self.client.get("https://api.mail.tm/domains")
            data = resp.json()
            domains = data.get("hydra:member", data) if isinstance(data, dict) else data
            if not domains:
                return "[-] mail.tm has no available domains right now."
            
            domain = domains[0]["domain"]
            
            # Step 2: Generate random username
            username = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
            address = f"{username}@{domain}"
            password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
            
            # Step 3: Create account
            create_resp = await self.client.post(
                "https://api.mail.tm/accounts",
                json={"address": address, "password": password}
            )
            create_data = create_resp.json()
            
            if create_resp.status_code == 201 or create_data.get("id"):
                report = (
                    "[+] mail.tm inbox created\n"
                    f"[+] Email: {address}\n"
                    f"[+] Password: {password}\n"
                    f"[+] Account ID: {create_data.get('id', 'unknown')}\n"
                    "\n"
                    "To check for emails:\n"
                    f"  set check {address}\n"
                    "  run\n"
                    "\n"
                    "Or visit: https://mail.tm"
                )
                return report
            
            # Handle errors
            error_msg = create_data.get("detail", "Unknown error")
            if "address" in str(error_msg).lower() and "taken" in str(error_msg).lower():
                return "[-] mail.tm: generated address was taken. Try again."
            return f"[-] mail.tm account creation failed: {error_msg}"
            
        except Exception as e:
            return f"[-] mail.tm request failed: {type(e).__name__}: {e}"


    # ── maildrop (Selenium) ─────────────────────────────────────────────

    async def _create_maildrop(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service
        except ImportError:
            return (
                "[-] Selenium or webdriver-manager is not installed.\n"
                "[>] Install with: pip install selenium webdriver-manager\n"
                "[>] Or use provider fake.legal or mail.tm (no Selenium needed)"
            )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

        driver = None
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)

            # Generate a random mailbox name
            rand_str = "".join(random.choices(string.ascii_lowercase, k=10))
            address = f"{rand_str}@maildrop.cc"

            driver.get(f"https://maildrop.cc/inbox/?mailbox={rand_str}")
            wait = WebDriverWait(driver, 15)

            # Wait for the inbox page to load
            wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))

            report = (
                "[+] maildrop inbox created\n"
                f"[+] Email: {address}\n"
                f"[+] Inbox: https://maildrop.cc/inbox/?mailbox={rand_str}\n"
                "\n"
                "[!] maildrop uses Selenium — visit the inbox URL above to check messages.\n"
                "[>] Anyone can view this inbox; do not use for sensitive accounts."
            )
            return report
        except Exception as e:
            return f"[-] maildrop Selenium failed: {type(e).__name__}: {e}"
        finally:
            if driver:
                driver.quit()