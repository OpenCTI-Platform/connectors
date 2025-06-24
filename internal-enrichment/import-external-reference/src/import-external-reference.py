import os
import io
import ssl
import urllib.request
import re
import asyncio
import threading
import sys
import signal
import traceback
from typing import Dict
from asyncio import Queue

import cachetools
import yaml

import html2text
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import HTMLConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage

from playwright.async_api import async_playwright, Page, BrowserContext
from pycti import OpenCTIConnectorHelper, get_config_variable

MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_WORKERS = 4


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

        # Cache size
        raw_cache = os.environ.get(
            "IMPORT_EXTERNAL_REFERENCE_CACHE_SIZE",
            config.get("import_external_reference", {}).get("cache_size", 32),
        )
        try:
            cache_size = int(raw_cache)
            if cache_size <= 0:
                raise ValueError
        except ValueError:
            self.helper.log_warning(
                f"Invalid cache size '{raw_cache}', defaulting to 32"
            )
            cache_size = 32

        # Worker count
        raw_workers = os.environ.get("BROWSER_WORKER_COUNT", DEFAULT_WORKERS)
        try:
            workers = int(raw_workers)
            if workers <= 0:
                raise ValueError
        except ValueError:
            self.helper.log_warning(
                f"Invalid worker count '{raw_workers}', "
                f"defaulting to {DEFAULT_WORKERS}"
            )
            workers = DEFAULT_WORKERS
        self.worker_count = workers

        # Thread-safe LRU cache
        self._download_cache = cachetools.LRUCache(maxsize=cache_size)
        self._cache_lock = threading.Lock()

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        self.helper.connector_logger.info(
            f"Config → import_as_pdf={self.import_as_pdf}, "
            f"import_as_md={self.import_as_md}, "
            f"import_pdf_as_md={self.import_pdf_as_md}, "
            f"cache_size={cache_size}, workers={self.worker_count}"
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
                if length and int(length) > MAX_DOWNLOAD_SIZE:
                    raise ValueError(f"Content-Length {length} exceeds limit")
                data = resp.read(MAX_DOWNLOAD_SIZE + 1)
                if not data:
                    raise ValueError("Downloaded data is empty")
                if len(data) > MAX_DOWNLOAD_SIZE:
                    raise ValueError("Downloaded data exceeds size limit")
        except Exception as e:
            self.helper.log_warning(
                f"Download failed ({url}): {e}"
            )
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

    async def _browser_worker(self):
        while True:
            try:
                url, fut = await self.task_queue.get()
                self.helper.log_debug(f"Dequeued task for: {url}")
                ctx = await self.browser.new_context(
                    user_agent=self.headers["User-Agent"]
                )
                page: Page = await ctx.new_page()
                try:
                    await page.route("**/*", self._block_resource)
                    try:
                        await asyncio.wait_for(
                            page.goto(
                                url,
                                wait_until="networkidle",
                                timeout=180000
                            ),
                            timeout=180
                        )
                        await page.wait_for_load_state("networkidle")
                    except asyncio.TimeoutError:
                        self.helper.log_warning(f"Timeout loading {url}")
                        if not fut.done():
                            fut.set_exception(
                                asyncio.TimeoutError(f"Timeout loading {url}")
                            )
                        continue
                    except Exception as e:
                        self.helper.log_warning(
                            f"Page.goto failed for {url}: {e}"
                        )
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
                            "right": "15mm"
                        },
                        scale=0.9,
                    )
                    if not pdf_bytes.startswith(b"%PDF"):
                        raise RuntimeError("Invalid PDF binary")

                    if not fut.done():
                        fut.set_result((html, pdf_bytes))

                except asyncio.CancelledError:
                    self.helper.log_warning(
                        f"Worker cancelled while processing {url}"
                    )
                    if not fut.done():
                        fut.set_exception(
                            asyncio.CancelledError(
                                f"Worker cancelled for {url}"
                            )
                        )
                except Exception as e:
                    self.helper.log_warning(f"Worker error ({url}): {e}")
                    if not fut.done():
                        fut.set_exception(e)
                finally:
                    await page.close()
                    await ctx.close()
                    self.task_queue.task_done()
                    self.helper.log_info(
                        f"Worker finished for {url}"
                    )

            except asyncio.CancelledError:
                break
            except Exception as fatal:
                self.helper.connector_logger.error(
                    f"Fatal worker error: {fatal}"
                )

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
    async def _process_external_reference(
                self, external_reference: Dict
            ) -> str:
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
            if is_pdf and (self.import_as_pdf or
                           (self.import_as_md and self.import_pdf_as_md)):
                pdf_data = self._download_url(url)
                if not pdf_data.startswith(b"%PDF"):
                    raise RuntimeError("Downloaded file is not a valid PDF")

            # Import as PDF
            if self.import_as_pdf:
                self.helper.log_debug("Beginning PDF import logic")
                try:
                    if is_pdf:
                        # Already downloaded above
                        file_name = os.path.basename(url)
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
                        file_name = os.path.basename(url) + ".pdf"
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
                        device = HTMLConverter(
                            rsrcmgr, html_buf, laparams=LAParams()
                        )
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

                except asyncio.TimeoutError:
                    self.helper.log_warning(
                        f"Markdown import timed out for {url}"
                    )
                except asyncio.CancelledError:
                    self.helper.log_warning(
                        f"Markdown import cancelled for {url}"
                    )
                except Exception as e:
                    self.helper.log_error(
                        f"Markdown import failed: {e}"
                    )

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
            args=["--disable-dev-shm-usage"],
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
            loop.add_signal_handler(
                sig, lambda: loop.call_soon_threadsafe(loop.stop)
            )

        # 4) launch the OpenCTI listen() in its own thread
        def _listen_in_thread():
            asyncio.run(
                self.helper.listen(message_callback=self._on_message)
            )

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
