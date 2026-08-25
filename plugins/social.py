from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from .base import BasePlugin


@dataclass(frozen=True)
class SiteSpec:
    name: str
    url: str
    not_found: tuple[str, ...] = ()
    blocked_statuses: tuple[int, ...] = (403, 429)
    positive_statuses: tuple[int, ...] = (200,)


class SocialIntel(BasePlugin):
    """Sherlock-style public profile checks with conservative false-positive handling."""

    SITES = (
        SiteSpec("GitHub", "https://github.com/{username}"),
        SiteSpec("GitLab", "https://gitlab.com/{username}"),
        SiteSpec("Reddit", "https://www.reddit.com/user/{username}"),
        SiteSpec("X / Twitter", "https://x.com/{username}"),
        SiteSpec("Instagram", "https://www.instagram.com/{username}/"),
        SiteSpec("Facebook", "https://www.facebook.com/{username}"),
        SiteSpec("Twitch", "https://www.twitch.tv/{username}"),
        SiteSpec("YouTube", "https://www.youtube.com/@{username}"),
        SiteSpec("TikTok", "https://www.tiktok.com/@{username}"),
        SiteSpec("Pinterest", "https://www.pinterest.com/{username}/"),
        SiteSpec("Medium", "https://medium.com/@{username}"),
        SiteSpec("Dev.to", "https://dev.to/{username}"),
        SiteSpec("Keybase", "https://keybase.io/{username}"),
        SiteSpec("Hacker News", "https://news.ycombinator.com/user?id={username}"),
        SiteSpec("Steam", "https://steamcommunity.com/id/{username}"),
        SiteSpec("Codeberg", "https://codeberg.org/{username}"),
        SiteSpec("Docker Hub", "https://hub.docker.com/u/{username}"),
        SiteSpec("PyPI", "https://pypi.org/user/{username}/"),
        SiteSpec("NPM", "https://www.npmjs.com/~{username}"),
        SiteSpec("Kaggle", "https://www.kaggle.com/{username}"),
        SiteSpec("Mastodon", "https://mastodon.social/@{username}"),
        SiteSpec("About.me", "https://about.me/{username}"),
        SiteSpec("Bandcamp", "https://{username}.bandcamp.com"),
        SiteSpec("Last.fm", "https://www.last.fm/user/{username}"),
        SiteSpec("SoundCloud", "https://soundcloud.com/{username}"),
        SiteSpec("Lichess", "https://lichess.org/@/{username}"),
        SiteSpec("Chess.com", "https://www.chess.com/member/{username}"),
        SiteSpec("Patreon", "https://www.patreon.com/{username}"),
        SiteSpec("Behance", "https://www.behance.net/{username}"),
        SiteSpec("Dribbble", "https://dribbble.com/{username}"),
    )

    async def run_all(self, target):
        return await self.sherlock_clone(target)

    async def run_sub(self, sub_id, target):
        if sub_id in {"sub_sherlock", "alias_search"}:
            return await self.sherlock_clone(target)
        return "[!] Social tool is not registered."

    async def sherlock_clone(self, username):
        username = username.strip().lstrip("@").split()[0] if username.strip() else ""
        if not username or len(username) > 64:
            return "[!] Provide one public username, without a password or private account information."
        results = [
            f"[>] Sherlock-style public username scan for: {username}",
            f"[>] Checking {len(self.SITES)} public platforms with bounded concurrency...",
            "[!] Found means the public page matched; it is not proof that all profiles belong to one person.",
        ]
        semaphore = asyncio.Semaphore(6)

        async def check(site: SiteSpec) -> str:
            url = site.url.format(username=username)
            async with semaphore:
                for attempt in range(2):
                    try:
                        response = await self.client.get(
                            url,
                            follow_redirects=True,
                            headers={"User-Agent": "Scylla-Public-Profile-Check/1.0"},
                        )
                        final_url = str(response.url).lower()
                        body = response.text[:10000].lower()
                        if response.status_code in site.blocked_statuses:
                            return f"[!] {site.name}: Blocked or rate limited ({response.status_code}) ({url})"
                        if response.status_code in site.positive_statuses:
                            title_missing = "page not found" in body or "doesn't exist" in body or "not found" in body
                            redirected_away = site.name not in {"X / Twitter", "Facebook"} and username.lower() not in final_url and site.name not in {"YouTube"}
                            if title_missing or redirected_away:
                                return f"[-] {site.name}: Not Found ({url})"
                            return f"[+] {site.name}: Found ({url})"
                        if response.status_code == 404:
                            return f"[-] {site.name}: Not Found ({url})"
                        return f"[!] {site.name}: Could not verify (HTTP {response.status_code}) ({url})"
                    except (asyncio.TimeoutError, TimeoutError):
                        if attempt == 0:
                            await asyncio.sleep(0.25)
                            continue
                        return f"[!] {site.name}: Timeout ({url})"
                    except Exception as error:
                        return f"[!] {site.name}: Error ({type(error).__name__}) ({url})"
            return f"[!] {site.name}: Could not verify ({url})"

        checks = await asyncio.gather(*(check(site) for site in self.SITES))
        results.extend(checks)
        found = sum(result.startswith("[+]") for result in checks)
        blocked = sum(result.startswith("[!]") for result in checks)
        results.extend([
            f"[+] Scan complete. Found {found}/{len(self.SITES)} possible public profiles.",
            f"[!] {blocked} platforms need manual confirmation because they blocked, timed out, or could not be verified.",
        ])
        return "\n".join(results)
