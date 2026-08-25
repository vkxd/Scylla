import asyncio
import random
import string

from .base import BasePlugin


class TempMail(BasePlugin):
    """Disposable mailbox generator supporting multiple providers."""

    PROVIDERS = ["fake.legal", "anonbox", "maildrop"]

    async def run_all(self, target=None):
        provider = (target or "fake.legal").strip().lower()
        if provider not in self.PROVIDERS:
            return (
                f"[!] Unknown provider: {provider}\n"
                f"[>] Available providers: {', '.join(self.PROVIDERS)}\n"
                f"[>] Usage: set provider fake.legal"
            )
        if provider == "fake.legal":
            return await self._create_fake_legal()
        if provider == "anonbox":
            return await self._create_anonbox()
        if provider == "maildrop":
            return await self._create_maildrop()
        return f"[!] Provider '{provider}' is not implemented yet."

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

    # ── anonbox (Selenium) ──────────────────────────────────────────────

    async def _create_anonbox(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait
        except ImportError:
            return (
                "[-] Selenium is not installed.\n"
                "[>] Install it with: pip install selenium webdriver-manager\n"
                "[>] Or use provider fake.legal (no Selenium needed)"
            )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

        driver = None
        try:
            driver = webdriver.Chrome(options=options)
            driver.get("https://anonbox.net/en")
            wait = WebDriverWait(driver, 15)

            # anonbox shows your email on the page
            email_el = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "#email-address, .email-address, [data-email]"))
            )
            address = email_el.text.strip()
            if not address:
                # Fallback: try to find any email-like text
                address = driver.find_element(By.TAG_NAME, "body").text
                import re
                match = re.search(r'[\w.+-]+@anonbox\.\w+', address)
                address = match.group(0) if match else ""

            if not address or "@" not in address:
                return "[-] Could not extract anonbox email. The page layout may have changed."

            inbox_url = driver.current_url
            report = (
                "[+] anonbox inbox created\n"
                f"[+] Email: {address}\n"
                f"[+] Page: {inbox_url}\n"
                "\n"
                "[!] anonbox uses Selenium — emails appear on the page above.\n"
                "[>] Refresh the anonbox page to check for new messages."
            )
            return report
        except Exception as e:
            return f"[-] anonbox Selenium failed: {type(e).__name__}: {e}"
        finally:
            if driver:
                driver.quit()

    # ── maildrop (Selenium) ─────────────────────────────────────────────

    async def _create_maildrop(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.support.ui import WebDriverWait
        except ImportError:
            return (
                "[-] Selenium is not installed.\n"
                "[>] Install it with: pip install selenium webdriver-manager\n"
                "[>] Or use provider fake.legal (no Selenium needed)"
            )

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

        driver = None
        try:
            # Generate a random mailbox name
            rand_str = "".join(random.choices(string.ascii_lowercase, k=10))
            address = f"{rand_str}@maildrop.cc"

            driver = webdriver.Chrome(options=options)
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
