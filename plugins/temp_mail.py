import random
import string
from .base import BasePlugin

class TempMail(BasePlugin):
    async def run_all(self, target=None):
        # Using Maildrop API logic (No Selenium required, much faster)
        rand_str = ''.join(random.choices(string.ascii_lowercase, k=10))
        inbox = f"{rand_str}@maildrop.cc"
        report = f"Temporary Mail Generated:\n"
        report += f"Email: {inbox}\n"
        report += f"Inbox URL: https://maildrop.cc/inbox/?mailbox={rand_str}\n"
        report += "\n[!] Note: Maildrop API is used instead of Selenium for anonbox to ensure stability and speed."
        return report

    async def run_sub(self, sub_id, target):
        return await self.run_all()
