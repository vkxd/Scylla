import os
import re
import time
import hashlib
import mimetypes

from urllib.parse import urljoin, urlparse, urldefrag
from playwright.sync_api import sync_playwright


# ============================================================
# CONFIG
# ============================================================

MAX_PAGES = 100

# How long to let Framer render after the document loads
WAIT_AFTER_LOAD = 5

# How long Playwright is allowed to wait for navigation
NAVIGATION_TIMEOUT = 30000

OUTPUT_DIR = ""
ASSETS_DIR = ""

visited_urls = set()
page_urls = []
page_files = {}

captured_resources = {}


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url):

    url, _ = urldefrag(url)

    parsed = urlparse(url)

    path = parsed.path

    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    return parsed._replace(
        path=path,
        fragment=""
    ).geturl()


def normalize_resource_url(url):

    url, _ = urldefrag(url)

    return url


def is_http_url(url):

    return url.startswith(
        ("http://", "https://")
    )


def is_internal_url(url, domain):

    try:

        parsed = urlparse(url)

        return (
            parsed.scheme in ("http", "https")
            and parsed.netloc == domain
        )

    except Exception:

        return False


def safe_filename(value):

    return re.sub(
        r"[^a-zA-Z0-9._-]",
        "_",
        value
    )


# ============================================================
# PAGE FILENAMES
# ============================================================

def get_page_filename(url):

    parsed = urlparse(url)

    path = parsed.path.strip("/")

    if not path:

        return "index.html"

    path = path.rstrip("/")

    path = path.replace(
        "/",
        "_"
    )

    path = safe_filename(
        path
    )

    return f"{path}.html"


# ============================================================
# RESOURCE FILENAMES
# ============================================================

def get_resource_filename(
    url,
    content_type=None
):

    parsed = urlparse(url)

    filename = os.path.basename(
        parsed.path
    )

    if not filename:

        filename = "resource"

    filename = safe_filename(
        filename
    )

    filename = filename.split("?")[0]

    name, ext = os.path.splitext(
        filename
    )

    if not ext and content_type:

        guessed_ext = mimetypes.guess_extension(
            content_type.split(";")[0].strip()
        )

        if guessed_ext:

            ext = guessed_ext

    if not ext:

        ext = ".bin"

    url_hash = hashlib.sha256(
        url.encode("utf-8")
    ).hexdigest()[:12]

    return (
        f"{name}_"
        f"{url_hash}"
        f"{ext}"
    )


# ============================================================
# NETWORK CAPTURE
# ============================================================

def capture_response(response):

    url = response.url

    if not is_http_url(url):

        return

    try:

        content_type = (
            response.headers
            .get(
                "content-type",
                ""
            )
            .lower()
        )

    except Exception:

        content_type = ""

    # Don't save HTML pages as assets
    if "text/html" in content_type:

        return

    try:

        body = response.body()

    except Exception:

        return

    if not body:

        return

    try:

        filename = get_resource_filename(
            url,
            content_type
        )

        filepath = os.path.join(
            ASSETS_DIR,
            filename
        )

        os.makedirs(
            ASSETS_DIR,
            exist_ok=True
        )

        if not os.path.exists(
            filepath
        ):

            with open(
                filepath,
                "wb"
            ) as f:

                f.write(
                    body
                )

        normalized = normalize_resource_url(
            url
        )

        captured_resources[
            normalized
        ] = filepath

        print(
            f"    ↓ Captured: {url}"
        )

    except Exception as e:

        print(
            f"    ⚠ Resource error: {e}"
        )


# ============================================================
# FIND INTERNAL LINKS
# ============================================================

def find_internal_links(
    page,
    current_url,
    domain
):

    try:

        links = page.locator(
            "a[href]"
        ).evaluate_all(
            """
            links =>
                links.map(a => a.href)
            """
        )

    except Exception:

        return []

    results = []

    for link in links:

        if not link:

            continue

        if link.startswith(
            (
                "mailto:",
                "tel:",
                "javascript:"
            )
        ):

            continue

        absolute = normalize_url(
            urljoin(
                current_url,
                link
            )
        )

        if not is_internal_url(
            absolute,
            domain
        ):

            continue

        path = urlparse(
            absolute
        ).path.lower()

        ignored_extensions = (
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".webp",
            ".svg",
            ".ico",
            ".css",
            ".js",
            ".json",
            ".xml",
            ".pdf",
            ".zip",
            ".mp3",
            ".mp4",
            ".wav",
            ".woff",
            ".woff2",
            ".ttf",
            ".otf"
        )

        if path.endswith(
            ignored_extensions
        ):

            continue

        results.append(
            absolute
        )

    return list(
        dict.fromkeys(
            results
        )
    )


# ============================================================
# SAVE PAGE
# ============================================================

def save_page(
    url,
    content
):

    filename = get_page_filename(
        url
    )

    filepath = os.path.join(
        OUTPUT_DIR,
        filename
    )

    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            content
        )

    page_files[
        normalize_url(url)
    ] = filename

    return filepath


# ============================================================
# REWRITE PAGE LINKS
# ============================================================

def rewrite_page_links(
    content,
    current_url
):

    def replace_href(match):

        quote = match.group(1)

        original = match.group(2)

        if not original:

            return match.group(0)

        if original.startswith("#"):

            return match.group(0)

        if original.startswith(
            (
                "mailto:",
                "tel:",
                "javascript:"
            )
        ):

            return match.group(0)

        absolute = normalize_url(
            urljoin(
                current_url,
                original
            )
        )

        if absolute not in page_files:

            return match.group(0)

        local_file = page_files[
            absolute
        ]

        current_file = get_page_filename(
            current_url
        )

        if local_file == current_file:

            return (
                f'href={quote}'
                f'#{quote}'
            )

        return (
            f'href={quote}'
            f'{local_file}'
            f'{quote}'
        )

    return re.sub(
        r'href=(["\'])(.*?)\1',
        replace_href,
        content,
        flags=re.IGNORECASE
    )


# ============================================================
# REWRITE NETWORK RESOURCES
# ============================================================

def rewrite_resource_urls(
    content,
    current_url
):

    current_file = get_page_filename(
        current_url
    )

    current_path = os.path.join(
        OUTPUT_DIR,
        current_file
    )

    current_dir = os.path.dirname(
        current_path
    )

    def get_local_resource(
        resource_url
    ):

        resource_url = urldefrag(
            resource_url
        )[0]

        normalized = normalize_resource_url(
            resource_url
        )

        if normalized not in captured_resources:

            return None

        local_path = captured_resources[
            normalized
        ]

        relative = os.path.relpath(
            local_path,
            current_dir
        )

        return relative.replace(
            os.sep,
            "/"
        )

    # --------------------------------------------------------
    # src=
    # --------------------------------------------------------

    def replace_src(match):

        quote = match.group(1)

        original = match.group(2)

        absolute = urljoin(
            current_url,
            original
        )

        local = get_local_resource(
            absolute
        )

        if not local:

            return match.group(0)

        return (
            f'src={quote}'
            f'{local}'
            f'{quote}'
        )

    content = re.sub(
        r'src=(["\'])(.*?)\1',
        replace_src,
        content,
        flags=re.IGNORECASE
    )

    # --------------------------------------------------------
    # poster=
    # --------------------------------------------------------

    content = re.sub(
        r'poster=(["\'])(.*?)\1',
        replace_src,
        content,
        flags=re.IGNORECASE
    )

    # --------------------------------------------------------
    # resource href=
    # --------------------------------------------------------

    def replace_resource_href(match):

        quote = match.group(1)

        original = match.group(2)

        absolute = urljoin(
            current_url,
            original
        )

        local = get_local_resource(
            absolute
        )

        if not local:

            return match.group(0)

        return (
            f'href={quote}'
            f'{local}'
            f'{quote}'
        )

    content = re.sub(
        r'href=(["\'])(.*?)\1',
        replace_resource_href,
        content,
        flags=re.IGNORECASE
    )

    # --------------------------------------------------------
    # CSS url(...)
    # --------------------------------------------------------

    def replace_css_url(match):

        quote = match.group(1)

        original = match.group(2)

        absolute = urljoin(
            current_url,
            original
        )

        local = get_local_resource(
            absolute
        )

        if not local:

            return match.group(0)

        return (
            "url("
            f"{quote}"
            f"{local}"
            f"{quote}"
            ")"
        )

    content = re.sub(
        r'url\(\s*(["\']?)(.*?)\1\s*\)',
        replace_css_url,
        content,
        flags=re.IGNORECASE
    )

    return content


# ============================================================
# REWRITE ALL EXPORTED PAGES
# ============================================================

def rewrite_all_pages():

    print()
    print("=" * 60)
    print("🔗 CONNECTING EXPORTED WEBSITE")
    print("=" * 60)

    for url in page_urls:

        normalized = normalize_url(
            url
        )

        if normalized not in page_files:

            continue

        filename = page_files[
            normalized
        ]

        filepath = os.path.join(
            OUTPUT_DIR,
            filename
        )

        if not os.path.exists(
            filepath
        ):

            continue

        print(
            f"🔗 Rewriting {filename}"
        )

        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as f:

            content = f.read()

        # Local page navigation
        content = rewrite_page_links(
            content,
            url
        )

        # Local assets
        content = rewrite_resource_urls(
            content,
            url
        )

        with open(
            filepath,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                content
            )


# ============================================================
# CRAWLER
# ============================================================

def crawl_website(
    target_url
):

    target_url = normalize_url(
        target_url
    )

    domain = urlparse(
        target_url
    ).netloc

    queue = [
        target_url
    ]

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        context = browser.new_context(

            viewport={
                "width": 1920,
                "height": 1080
            },

            user_agent=(
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/139 Safari/537.36"
            )
        )

        page = context.new_page()

        # ====================================================
        # CAPTURE EVERY NETWORK RESPONSE
        # ====================================================

        page.on(
            "response",
            capture_response
        )

        # ====================================================
        # CRAWL PAGES
        # ====================================================

        while (
            queue
            and
            len(visited_urls) < MAX_PAGES
        ):

            current_url = queue.pop(
                0
            )

            current_url = normalize_url(
                current_url
            )

            if current_url in visited_urls:

                continue

            print()
            print("=" * 60)

            print(
                f"📄 PAGE "
                f"{len(visited_urls) + 1}"
            )

            print(
                f"🌐 {current_url}"
            )

            print("=" * 60)

            visited_urls.add(
                current_url
            )

            try:

                # =================================================
                # IMPORTANT:
                #
                # DO NOT use networkidle.
                #
                # Framer/Spotify/analytics can continuously
                # generate requests.
                # =================================================

                try:

                    page.goto(
                        current_url,
                        wait_until="domcontentloaded",
                        timeout=NAVIGATION_TIMEOUT
                    )

                except Exception as navigation_error:

                    error_text = str(
                        navigation_error
                    )

                    # If navigation timed out, check whether
                    # the document actually loaded.
                    print(
                        "⚠ Navigation timed out."
                    )

                    print(
                        "   Checking if page rendered..."
                    )

                    try:

                        title = page.title()

                        body_exists = page.locator(
                            "body"
                        ).count() > 0

                        if body_exists:

                            print(
                                f"✓ Page loaded anyway"
                                f" ({title})"
                            )

                        else:

                            print(
                                "❌ Page did not render."
                            )

                            print(
                                error_text
                            )

                            continue

                    except Exception:

                        print(
                            "❌ Could not recover "
                            "from navigation timeout."
                        )

                        continue

                # =================================================
                # WAIT FOR FRAMER
                # =================================================

                print(
                    "⏳ Waiting for Framer..."
                )

                time.sleep(
                    WAIT_AFTER_LOAD
                )

                # =================================================
                # SCROLL TO LOAD LAZY CONTENT
                # =================================================

                print(
                    "📜 Loading lazy content..."
                )

                try:

                    page.evaluate(
                        """
                        async () => {

                            const distance = 600;

                            let current = 0;

                            while (
                                current <
                                document.body.scrollHeight
                            ) {

                                window.scrollBy(
                                    0,
                                    distance
                                );

                                await new Promise(
                                    resolve =>
                                        setTimeout(
                                            resolve,
                                            150
                                        )
                                );

                                current += distance;
                            }

                            window.scrollTo(
                                0,
                                0
                            );
                        }
                        """
                    )

                    time.sleep(2)

                except Exception:

                    pass

                # =================================================
                # FIND SUBPAGES
                # =================================================

                links = find_internal_links(
                    page,
                    current_url,
                    domain
                )

                print(
                    f"🔎 Found "
                    f"{len(links)} internal links"
                )

                for link in links:

                    if (
                        link not in visited_urls
                        and
                        link not in queue
                    ):

                        queue.append(
                            link
                        )

                # =================================================
                # SAVE DOM
                # =================================================

                html = page.content()

                filepath = save_page(
                    current_url,
                    html
                )

                page_urls.append(
                    current_url
                )

                print(
                    f"✓ Saved: "
                    f"{filepath}"
                )

            except Exception as e:

                print()
                print(
                    f"❌ Failed: "
                    f"{current_url}"
                )

                print(
                    f"   {e}"
                )

        browser.close()

    # ========================================================
    # REWRITE EVERYTHING
    # ========================================================

    rewrite_all_pages()

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 60)
    print("🎉 EXPORT COMPLETE")
    print("=" * 60)

    print(
        f"📄 Pages captured: "
        f"{len(page_urls)}"
    )

    print(
        f"📦 Network resources: "
        f"{len(captured_resources)}"
    )

    print(
        f"📁 Folder:"
    )

    print(
        f"   {OUTPUT_DIR}"
    )

    print()
    print(
        "Open index.html to test the export."
    )

    print("=" * 60)


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    print()

    print(
        "╔══════════════════════════════════════╗"
    )

    print(
        "║       FRAMER WEBSITE EXPORTER        ║"
    )

    print(
        "║          NETWORK CAPTURE             ║"
    )

    print(
        "╚══════════════════════════════════════╝"
    )

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    target_url = input(
        "\n🌐 Enter your website URL: "
    ).strip()

    if not target_url.startswith(
        ("http://", "https://")
    ):

        target_url = (
            "https://"
            + target_url
        )

    # --------------------------------------------------------
    # Folder
    # --------------------------------------------------------

    folder_name = input(
        "📁 Enter a name for the export folder: "
    ).strip()

    if not folder_name:

        folder_name = (
            "exported_framer_rendered"
        )

    folder_name = re.sub(
        r'[<>:"/\\|?*]',
        "_",
        folder_name
    )

    OUTPUT_DIR = os.path.abspath(
        folder_name
    )

    ASSETS_DIR = os.path.join(
        OUTPUT_DIR,
        "assets"
    )

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    os.makedirs(
        ASSETS_DIR,
        exist_ok=True
    )

    print()
    print(
        "📂 Export location:"
    )

    print(
        f"   {OUTPUT_DIR}"
    )

    # --------------------------------------------------------
    # Run
    # --------------------------------------------------------

    crawl_website(
        target_url
    )