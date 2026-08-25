import asyncio

from .base import BasePlugin


class SocialIntel(BasePlugin):
    SITES = {
        "GitHub": "https://github.com/{}",
        "GitLab": "https://gitlab.com/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "X / Twitter": "https://x.com/{}",
        "Instagram": "https://www.instagram.com/{}/",
        "Facebook": "https://www.facebook.com/{}",
        "Twitch": "https://www.twitch.tv/{}",
        "YouTube": "https://www.youtube.com/@{}",
        "TikTok": "https://www.tiktok.com/@{}",
        "Pinterest": "https://www.pinterest.com/{}/",
        "Medium": "https://medium.com/@{}",
        "Dev.to": "https://dev.to/{}",
        "Keybase": "https://keybase.io/{}",
        "HackerNews": "https://news.ycombinator.com/user?id={}",
        "Steam": "https://steamcommunity.com/id/{}",
        "Codeberg": "https://codeberg.org/{}",
        "Docker Hub": "https://hub.docker.com/u/{}",
        "PyPI": "https://pypi.org/user/{}/",
        "NPM": "https://www.npmjs.com/~{}",
        "Kaggle": "https://www.kaggle.com/{}",
    }

    async def run_all(self, target):
        return await self.sherlock_clone(target)

    async def run_sub(self, sub_id, target):
        if sub_id == "sub_sherlock":
            return await self.sherlock_clone(target)
        return "[!] Social tool is not registered."

    async def sherlock_clone(self, username):
        results = [
            f"[>] Sherlock-style username scan for: {username}",
            f"[>] Checking {len(self.SITES)} public platforms...",
        ]
        semaphore = asyncio.Semaphore(8)

        async def check(site, url):
            async with semaphore:
                try:
                    response = await self.client.get(url.format(username), follow_redirects=True)
                    if response.status_code == 200:
                        return f"[+] {site}: Found ({url.format(username)})"
                    return f"[-] {site}: Not Found"
                except Exception as error:
                    return f"[!] {site}: Error ({type(error).__name__})"

        checks = await asyncio.gather(*(check(site, url) for site, url in self.SITES.items()))
        results.extend(checks)
        found = sum(result.startswith("[+]") for result in checks)
        results.append(f"[+] Scan complete. Found {found}/{len(self.SITES)} public profiles.")
        return "\n".join(results)
