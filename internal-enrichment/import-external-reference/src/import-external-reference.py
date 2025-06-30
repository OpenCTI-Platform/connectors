import asyncio
import datetime
import io
import os
import re
import signal
import ssl
import sys
import threading
import traceback
import urllib.request
from asyncio import Queue
from typing import Dict

import cachetools
import html2text
import yaml
from pdfminer.converter import HTMLConverter
from pdfminer.layout import LAParams
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage
from playwright.async_api import BrowserContext, Page, async_playwright
from pycti import OpenCTIConnectorHelper, get_config_variable


def is_valid_url(url: str) -> bool:
    return bool(re.match(r"^https?://", url.strip()))


class ImportExternalReferenceConnector:
    def __init__(self):
        # ─── Load & sanitize config ─────────────────────────────────────────
        cfg_path = os.path.join(os.path.dirname(__file__), "config.yml")
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config)

        self.import_as_pdf = get_config_variable(
            "IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_PDF",
            ["import_external_reference", "import_as_pdf"],
            config,
            False,
            True,
        )
        self.import_as_md = get_config_variable(
            "IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_MD",
            ["import_external_reference", "import_as_md"],
            config,
            False,
            True,
        )
        self.import_pdf_as_md = get_config_variable(
            "IMPORT_EXTERNAL_REFERENCE_IMPORT_PDF_AS_MD",
            ["import_external_reference", "import_pdf_as_md"],
            config,
            False,
            True,
        )
        self.timestamp_files = get_config_variable(
            "IMPORT_EXTERNAL_REFERENCE_TIMESTAMP_FILES",
            ["import_external_reference", "timestamp_files"],
            config,
            False,
            False,  # Default to False
        )
        self.cache_size = get_config_variable(
            "IMPORT_EXTERNAL_REFERENCE_CACHE_SIZE",
            ["import_external_reference", "cache_size"],
            config,
            True,
            32,  # Default to 32 MB
        )
        self.worker_count = get_config_variable(
            "IMPORT_EXTERNAL_REFERENCE_BROWSER_WORKER_COUNT",
            ["import_external_reference", "browser_worker_count"],
            config,
            True,
            4,  # Default to 4 workers
        )

        # Max download size (in bytes)
        self.max_download_size = get_config_variable(
            "IMPORT_EXTERNAL_REFERENCE_MAX_DOWNLOAD_SIZE",
            ["import_external_reference", "max_download_size"],
            config,
            True,
            50 * 1024 * 1024,  # Default to 50 MB
        )

        # Thread-safe LRU cache
        self._download_cache = cachetools.LRUCache(maxsize=self.cache_size)
        self._cache_lock = threading.Lock()

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Microsoft Edge";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
        }

        self.helper.connector_logger.info(
            f"Config → import_as_pdf={self.import_as_pdf}, "
            f"import_as_md={self.import_as_md}, "
            f"import_pdf_as_md={self.import_pdf_as_md}, "
            f"cache_size={self.cache_size}, workers={self.worker_count}"
        )

        # Will be set in start()
        self.browser: BrowserContext = None  # type: ignore
        self.playwright = None
        self.task_queue: Queue = None  # type: ignore
        self.workers = []
        self.loop: asyncio.AbstractEventLoop = None  # type: ignore

    # ────────────────────────────────────────────────────────────────────────────────
    # DOWNLOAD & CACHE
    # ────────────────────────────────────────────────────────────────────────────────
    def _download_url(self, url: str) -> bytes:
        with self._cache_lock:
            if url in self._download_cache:
                self.helper.connector_logger.debug(f"Cache hit: {url}")
                return self._download_cache[url]

        self.helper.connector_logger.debug(f"Cache miss: {url}")
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(
                req, context=ssl.create_default_context(), timeout=180
            ) as resp:
                length = resp.headers.get("Content-Length")
                if length and int(length) > self.max_download_size:
                    raise ValueError(f"Content-Length {length} exceeds limit")
                data = resp.read(self.max_download_size + 1)
                if not data:
                    raise ValueError("Downloaded data is empty")
                if len(data) > self.max_download_size:
                    raise ValueError("Downloaded data exceeds size limit")
        except Exception as e:
            self.helper.log_warning(f"Download failed ({url}): {e}")
            raise

        with self._cache_lock:
            self._download_cache[url] = data
        return data

    # ────────────────────────────────────────────────────────────────────────────────
    # PLAYWRIGHT WORKERS
    # ────────────────────────────────────────────────────────────────────────────────
    async def _block_resource(self, route, request):
        # Only block media to speed up load; allow CSS/JS so pages render
        if request.resource_type in ("media"):
            await route.abort()
        else:
            await route.continue_()

    async def _dismiss_cookies(self, page: Page) -> bool:
        """
        Attempts to dismiss cookies or consent banners/popups on a web page asynchronously.
        Uses a broad set of selectors and strategies for robustness, but only clicks visible, enabled, interactive elements.
        :param page: The Playwright Page object representing the current web page.
        :return: bool: Returns True if any consent/banner element was successfully handled, otherwise False.
        """
        found = False
        # Broader selectors: id/class, case-insensitive, more keywords
        keywords = [
            "accept",
            "agree",
            "allow",
            "consent",
            "continue",
            "got it",
            "understand",
            "ok",
            "yes",
            "close",
            "dismiss",
        ]
        selectors = []
        for kw in keywords:
            selectors.extend(
                [
                    f'button:has-text("{kw}")',
                    f'a:has-text("{kw}")',
                    f'[id*="{kw}"]',
                    f'[class*="{kw}"]',
                ]
            )
        # Try clicking only the first visible, enabled, interactive element for each selector
        for selector in selectors:
            try:
                locs = page.locator(selector)
                count = await locs.count()
                if count == 0:
                    continue
                for i in range(count):
                    el = locs.nth(i)
                    try:
                        # Only click if visible and enabled
                        if not await el.is_visible() or not await el.is_enabled():
                            continue
                        # For generic id/class selectors, only click if tag is button or a
                        tag = (await el.evaluate("el => el.tagName")).lower()
                        if selector.startswith("[id*") or selector.startswith(
                            "[class*"
                        ):
                            if tag not in ("button", "a"):
                                continue
                        await el.click(timeout=1000, force=True)
                        found = True
                        self.helper.connector_logger.debug(
                            f"Clicked cookie/banner selector: {selector} (index {i})"
                        )
                        # After a successful click, break for this selector
                        await asyncio.sleep(0.5)
                        break
                    except Exception as e:
                        self.helper.connector_logger.debug(
                            f"Failed to click {selector} (index {i}): {e}"
                        )
                if found:
                    break
            except Exception:
                continue
        # Fallback: try to hide/remove banners/popups via JS if nothing was clicked
        if not found:
            try:
                await page.evaluate(
                    """
                    const keywords = ["cookie", "consent", "banner", "popup", "gdpr", "privacy", "notice", "modal", "alert", "dialog"];
                    let removed = false;
                    for (const kw of keywords) {
                        const els = [
                            ...document.querySelectorAll(`[id*='${kw}'], [class*='${kw}']`)
                        ];
                        for (const el of els) {
                            if (el && el.style) {
                                el.style.display = 'none';
                                removed = true;
                            }
                        }
                    }
                    return removed;
                    """
                )
                self.helper.connector_logger.debug(
                    "Ran JS fallback to hide banners/popups."
                )
            except Exception as e:
                self.helper.connector_logger.debug(
                    f"JS fallback for hiding banners failed: {e}"
                )
        return found

    async def _browser_worker(self):
        while True:
            try:
                url, fut = await self.task_queue.get()
                self.helper.log_debug(f"Dequeued task for: {url}")
                ctx = None
                page = None
                try:
                    ctx = await self.browser.new_context(
                        user_agent=self.headers["User-Agent"],
                        ignore_https_errors=True,
                        viewport={"width": 1280, "height": 800},
                        extra_http_headers=self.headers,
                    )
                    await ctx.add_init_script(
                        """
                        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                        Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
                        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                        window.chrome = { runtime: {}, loadTimes: () =>  { return null; }, csi: () => { return {}; } };
                        """
                    )
                    page = await ctx.new_page()

                    async def handle_response(response):
                        try:
                            if response.status in (403, 429, 503):
                                text = await response.text()

                                self.helper.log_info(
                                    f"WAF-style block: {response.status} on {response.url}"
                                )

                                # Normalize content
                                lower_text = text.lower()

                                # General detections
                                if "captcha" in lower_text:
                                    self.helper.log_info("Detected CAPTCHA challenge")

                                if (
                                    "cloudflare" in lower_text
                                    or "checking your browser" in text
                                ):
                                    self.helper.log_info(
                                        "Detected Cloudflare JS challenge"
                                    )

                                if "__cf_bm" not in [
                                    c["name"]
                                    for c in await response.request.context.cookies()
                                ]:
                                    self.helper.log_info(
                                        "Cloudflare cookie (__cf_bm) not present"
                                    )

                                # Akamai
                                if "_abck" in text or "akamai" in lower_text:
                                    self.helper.log_info(
                                        "Possible Akamai Bot Manager block detected (_abck cookie or content match)"
                                    )

                                # Imperva
                                if (
                                    "incapsula" in lower_text
                                    or "x-iinfo" in response.headers
                                ):
                                    self.helper.log_info(
                                        "Possible Imperva/Incapsula block (x-iinfo header or content match)"
                                    )

                                # AWS WAF
                                if (
                                    "aws-waf" in lower_text
                                    or "awsalb"
                                    in response.headers.get("server", "").lower()
                                ):
                                    self.helper.log_info(
                                        "Possible AWS WAF or ALB layer block"
                                    )

                                # F5
                                if (
                                    "f5" in lower_text
                                    or "big-ip"
                                    in response.headers.get("set-cookie", "").lower()
                                ):
                                    self.helper.log_info(
                                        "Possible F5 BIG-IP block (cookie or content match)"
                                    )

                                # Fastly
                                if (
                                    "fastly" in lower_text
                                    or "x-served-by" in response.headers
                                    and "fastly"
                                    in response.headers["x-served-by"].lower()
                                ):
                                    self.helper.log_info(
                                        "Fastly block indicators found"
                                    )

                                # Generic automation block indicators
                                if (
                                    "access denied" in lower_text
                                    or "request blocked" in lower_text
                                ):
                                    self.helper.log_info(
                                        "Generic access denial or bot detection trigger"
                                    )

                        except Exception as e:
                            self.helper.log_warning(f"Response diagnostics failed: {e}")

                    # Add listener before navigation
                    page.on("response", handle_response)

                    await page.route("**/*", self._block_resource)
                    try:

                        async def _safe_navigate(page: Page, url: str):
                            await page.goto(url, wait_until="domcontentloaded")
                            await asyncio.sleep(5)  # let JS challenges resolve
                            await page.wait_for_load_state(
                                "load"
                            )  # still useful for complete render

                        await asyncio.wait_for(
                            asyncio.shield(_safe_navigate(page, url)), timeout=180
                        )

                        # Wait a short time for banners/popups to appear
                        await asyncio.sleep(1.5)
                        # Dismiss cookies or consent banners
                        await self._dismiss_cookies(page)

                    except asyncio.TimeoutError:
                        self.helper.log_warning(f"Timeout loading {url}")
                        if not fut.done():
                            fut.set_exception(
                                asyncio.TimeoutError(f"Timeout loading {url}")
                            )
                        continue
                    except Exception as e:
                        self.helper.log_warning(f"Page.goto failed for {url}: {e}")
                        if not fut.done():
                            fut.set_exception(e)
                        continue

                    html = await page.content()
                    if "<html" not in html.lower():
                        raise RuntimeError("Malformed or empty HTML")

                    pdf_bytes = await page.pdf(
                        format="A4",
                        margin={
                            "top": "10mm",
                            "bottom": "10mm",
                            "left": "15mm",
                            "right": "15mm",
                        },
                        scale=0.9,
                    )
                    if not pdf_bytes.startswith(b"%PDF"):
                        raise RuntimeError("Invalid PDF binary")

                    if not fut.done():
                        fut.set_result((html, pdf_bytes))

                except asyncio.CancelledError:
                    self.helper.log_warning(f"Worker cancelled while processing {url}")
                    if not fut.done():
                        fut.set_exception(
                            asyncio.CancelledError(f"Worker cancelled for {url}")
                        )
                except Exception as e:
                    self.helper.log_warning(f"Worker error ({url}): {e}")
                    if not fut.done():
                        fut.set_exception(e)
                finally:
                    if page is not None:
                        await page.close()
                    if ctx is not None:
                        await ctx.close()
                    self.task_queue.task_done()
                    self.helper.log_info(f"Worker finished for {url}")

            except asyncio.CancelledError:
                break
            except Exception as fatal:
                self.helper.connector_logger.error(f"Fatal worker error: {fatal}")

    async def _cleanup(self):
        for w in self.workers:
            w.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)

        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    # ────────────────────────────────────────────────────────────────────────────────
    # CORE FETCH
    # ────────────────────────────────────────────────────────────────────────────────
    async def _fetch_with_browser(self, url: str, timeout: int = 180):
        self.helper.log_debug(f"Queueing fetch task for: {url}")
        fut = asyncio.get_running_loop().create_future()
        await self.task_queue.put((url, fut))
        self.helper.log_debug(
            f"Task queued for: {url} (queue size: {self.task_queue.qsize()})"
        )
        return await asyncio.wait_for(fut, timeout=timeout)

    # ────────────────────────────────────────────────────────────────────────────────
    # ACTUAL IMPORT LOGIC (ASYNC)
    # ────────────────────────────────────────────────────────────────────────────────
    async def _process_external_reference(self, external_reference: Dict) -> str:
        try:
            self.helper.log_info("Processing external reference…")
            url = external_reference.get("url", "").strip()
            if not url or not is_valid_url(url):
                raise ValueError(f"Invalid or missing URL: {url!r}")

            is_pdf = url.lower().endswith(".pdf")
            pdf_data = None

            self.helper.log_debug(
                f"External reference details: "
                f"id={external_reference.get('id')}, "
                f"url={url}, is_pdf={is_pdf}"
            )

            # Pre-download PDF if needed
            if is_pdf and (
                self.import_as_pdf or (self.import_as_md and self.import_pdf_as_md)
            ):
                pdf_data = self._download_url(url)
                if not pdf_data.startswith(b"%PDF"):
                    raise RuntimeError("Downloaded file is not a valid PDF")

            # Import as PDF
            if self.import_as_pdf:
                self.helper.log_debug("Beginning PDF import logic")
                try:
                    if is_pdf:
                        # Already downloaded above
                        file_name = self._safe_filename_from_url(url)
                        self.helper.log_info(
                            f"Attaching file '{file_name}' "
                            f"to {external_reference['id']}"
                        )
                        try:
                            self.helper.api.external_reference.add_file(
                                id=external_reference["id"],
                                file_name=file_name,
                                data=pdf_data,
                                mime_type="application/pdf",
                            )
                        except Exception as api_err:
                            self.helper.log_error(
                                f"OpenCTI API file attach failed: {api_err}"
                            )
                    else:
                        # Render via Playwright
                        html, pdf_bytes = await self._fetch_with_browser(url)
                        file_name = self._safe_filename_from_url(url, ".pdf")
                        self.helper.log_info(
                            f"Attaching file '{file_name}' "
                            f"to {external_reference['id']}"
                        )
                        try:
                            self.helper.api.external_reference.add_file(
                                id=external_reference["id"],
                                file_name=file_name,
                                data=pdf_bytes,
                                mime_type="application/pdf",
                            )
                        except Exception as api_err:
                            self.helper.log_error(
                                f"OpenCTI API file attach failed: {api_err}"
                            )
                except Exception as e:
                    self.helper.log_error(f"PDF import failed: {e}")

            # Import as Markdown
            if self.import_as_md:
                self.helper.log_debug("Beginning Markdown import logic")
                # Configure html2text
                text_maker = html2text.HTML2Text()
                text_maker.body_width = 0
                text_maker.ignore_links = False
                text_maker.ignore_images = False
                text_maker.ignore_tables = False
                text_maker.ignore_emphasis = False
                text_maker.skip_internal_links = False
                text_maker.inline_links = True
                text_maker.protect_links = True
                text_maker.mark_code = True

                try:
                    if is_pdf and self.import_pdf_as_md:
                        # Convert the downloaded PDF to HTML, then to Markdown
                        pdf_stream = io.BytesIO(pdf_data)
                        html_buf = io.StringIO()
                        rsrcmgr = PDFResourceManager(caching=True)
                        device = HTMLConverter(rsrcmgr, html_buf, laparams=LAParams())
                        interpreter = PDFPageInterpreter(rsrcmgr, device)
                        for page in PDFPage.get_pages(
                            pdf_stream, check_extractable=True
                        ):
                            interpreter.process_page(page)
                        device.close()

                        md = text_maker.handle(html_buf.getvalue())
                        file_name = os.path.basename(url) + ".md"
                        self.helper.log_info(
                            f"Attaching file '{file_name}' "
                            f"to {external_reference['id']}"
                        )
                        try:
                            self.helper.api.external_reference.add_file(
                                id=external_reference["id"],
                                file_name=file_name,
                                data=md,
                                mime_type="text/markdown",
                            )
                        except Exception as api_err:
                            self.helper.log_error(
                                f"OpenCTI API file attach failed: {api_err}"
                            )

                    elif not is_pdf:
                        # Render page, grab its HTML, and convert to Markdown
                        html, _ = await self._fetch_with_browser(url)
                        md = text_maker.handle(html)
                        # Fix protocol-relative links
                        md = md.replace("](//", "](https://")
                        file_name = self._safe_filename_from_url(url, ".md")
                        self.helper.log_info(
                            f"Attaching file '{file_name}' "
                            f"to {external_reference['id']}"
                        )
                        try:
                            self.helper.api.external_reference.add_file(
                                id=external_reference["id"],
                                file_name=file_name,
                                data=md,
                                mime_type="text/markdown",
                            )
                        except Exception as api_err:
                            self.helper.log_error(
                                f"OpenCTI API file attach failed: {api_err}"
                            )

                except asyncio.TimeoutError:
                    self.helper.log_warning(f"Markdown import timed out for {url}")
                except asyncio.CancelledError:
                    self.helper.log_warning(f"Markdown import cancelled for {url}")
                except Exception as e:
                    self.helper.log_error(f"Markdown import failed: {e}")

            return "Import complete."
        except asyncio.TimeoutError:
            self.helper.log_warning(
                f"Enrichment timed out for {external_reference.get('url')}"
            )
            return "Timeout"
        except asyncio.CancelledError:
            self.helper.log_warning(
                f"Enrichment cancelled for {external_reference.get('url')}"
            )
            return "Cancelled"
        except Exception as e:
            self.helper.log_error(
                f"Enrichment failed for {external_reference.get('url')}: {e}"
            )
            return f"Failed: {e}"

    # ────────────────────────────────────────────────────────────────────────────────
    # SYNC CALLBACK FOR OPENCTI
    # ────────────────────────────────────────────────────────────────────────────────
    def _on_message(self, data: Dict) -> str:
        """
        This is the *synchronous* callback that OpenCTI invokes in its worker
        thread. We schedule the real async work onto our event loop, and
        immediately return a JSON-serializable acknowledgement.
        """
        self.helper.log_debug(f"Received raw message: {data}")

        ext_ref = data.get("enrichment_entity", {})

        self.helper.log_debug(
            f"Received enrichment_entity: {ext_ref if ext_ref else 'None'}"
        )

        self.helper.log_info(
            f"Dispatching enrichment task for external-reference: "
            f"{ext_ref.get('id')}, url={ext_ref.get('url')}"
        )

        future = asyncio.run_coroutine_threadsafe(
            self._process_external_reference(ext_ref), self.loop
        )

        def _log_done(fut: asyncio.Future):
            try:
                result = fut.result()
                self.helper.log_info(
                    f"Processed reference {ext_ref.get('id')}: {result}"
                )
            except Exception as e:
                self.helper.log_error(
                    f"Error processing reference {ext_ref.get('id')}: {e}"
                )

        future.add_done_callback(_log_done)
        return "OK"

    def _safe_filename_from_url(self, url: str, suffix: str = "") -> str:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.rstrip("/")
        base = os.path.basename(path)
        if not base:
            base = parsed.netloc or "external-reference"
        if self.timestamp_files:
            ts = datetime.datetime.utcnow().strftime("_%Y%m%d_%H%M%S")
            if suffix and base.endswith(suffix):
                base = base[: -len(suffix)]
            base += ts
        if suffix and not base.endswith(suffix):
            base += suffix
        return base

    # ────────────────────────────────────────────────────────────────────────────────
    # START / STOP
    # ────────────────────────────────────────────────────────────────────────────────
    async def _init_async(self):
        """
        Launch Playwright, spin up the browser, set up the queue and workers.
        Does NOT start `listen()`.
        """
        self.helper.connector_logger.info("▶ entering _init_async")
        self.loop = asyncio.get_running_loop()

        # 1) start Playwright and the browser
        pw = await async_playwright().start()
        self.playwright = pw
        self.helper.connector_logger.info("▶ launching browser…")
        self.browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--ignore-certificate-errors",
                "--disable-blink-features=AutomationControlled",  # Disable WebDriver detection for WAF bypass
            ],
        )
        self.helper.connector_logger.info("▶ browser launched")

        # 2) task queue and workers
        # Set task queue size to match worker count (prevents over-buffering)
        self.task_queue = Queue(maxsize=self.worker_count)

        self.helper.connector_logger.info("▶ browser workers starting")
        self.workers = [
            asyncio.create_task(self._browser_worker())
            for _ in range(self.worker_count)
        ]
        self.helper.connector_logger.info(
            f"Started {self.worker_count} browser workers"
        )

    def start(self):
        # 1) new loop & set it
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # 2) bootstrap browser, queue, workers
        loop.run_until_complete(self._init_async())

        # 3) register clean-shutdown on Ctrl-C or SIGTERM
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: loop.call_soon_threadsafe(loop.stop))

        # 4) launch the OpenCTI listen() in its own thread
        def _listen_in_thread():
            asyncio.run(self.helper.listen(message_callback=self._on_message))

        t = threading.Thread(target=_listen_in_thread, daemon=True)
        t.start()

        # 5) let the loop run until stopped by signal
        try:
            loop.run_forever()
        finally:
            # this will run when loop.stop() is called
            loop.run_until_complete(self._cleanup())


if __name__ == "__main__":
    try:
        ImportExternalReferenceConnector().start()
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
