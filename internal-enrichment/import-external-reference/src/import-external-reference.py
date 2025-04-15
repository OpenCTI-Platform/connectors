import os
import ssl
import urllib.request
from typing import Dict

import html2text
import yaml
from pdfminer.converter import HTMLConverter
from pdfminer.layout import LAParams
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage
from playwright.sync_api import Error, sync_playwright
from pycti import OpenCTIConnectorHelper, get_config_variable


class ImportExternalReferenceConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
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
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64)"}

    def delete_files(self):
        if os.path.exists("data.html"):
            os.remove("data.html")
        if os.path.exists("data.pdf"):
            os.remove("data.pdf")

    def _is_cookies_accepted(self, page):
        """
        Attempts to accept cookies on a web page.
        This method searches for various elements (links and buttons) that are commonly used for cookie consent prompts.
        It uses a list of predefined selectors to identify and click on elements that contain text variations related to cookie acceptance.

        :param page: The Playwright Page object representing the current web page.
        :return: bool: Returns True if a cookie acceptance element was successfully clicked, otherwise returns False.
        """

        found = False

        selectors = [
            'a:has-text("agree")',
            'button:has-text("agree")',
            'a:has-text("accept all")',
            'button:has-text("accept all")',
            'a:has-text("accept")',
            'button:has-text("accept")',
            'a:has-text("i agree")',
            'button:has-text("i agree")',
            'a:has-text("allow")',
            'button:has-text("allow")',
        ]

        for selector in selectors:
            try:
                page.locator(selector).first.click(timeout=1000, force=True)
                found = True
                break
            except Error as error:
                self.helper.connector_logger.debug(
                    "A playwrigth error has been identified when using locator",
                    {
                        "name": str(error.name),
                        "message": str(error.message),
                        "selector": selector,
                    },
                )
                continue
            except Exception as e:
                self.helper.connector_logger.error(
                    "An unknown error occurred when using the locator",
                    {"error": str(e), "selector": selector},
                )
                continue
        return found

    @staticmethod
    def _hides_unwanted_elements(page):
        """
        Hides unwanted elements of the page to improve the readability of the pdf if the click to accept cookies has failed.
        :param page: The Playwright Page object representing the current web page.
        :return: None
        """

        page.evaluate(
            """
        const elements = document.querySelectorAll('[id*="popup"], [class*="popup"], [id*="cookie"], [class*="cookie"], [id*="privacy"], [class*="privacy"], [id*="consent"], [class*="consent"]');
        elements.forEach(el => el.style.display = 'none');
        """
        )

    def _process_playwright(self, p, url_to_import):
        """
        Launches a Playwright browser instance, navigates to the specified URL, and performs actions such as simulating
        a user environment and handling cookie consent pop-ups.

        :param p: The Playwright instance used to interact with the browser (e.g., `playwright`).
        :param url_to_import: The URL of the page to load in the browser.
        :return: A tuple containing the browser and page objects.
                 - browser: The launched browser instance.
                 - page: The browser page object used to interact with the loaded web page.
        """
        browser = p.chromium.launch()

        # Create a new browser context with a specified user agent to simulate a particular browser
        # environment, which helps to bypass certain security measures.
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        page.goto(url_to_import)

        is_cookies_accepted = self._is_cookies_accepted(page)

        if not is_cookies_accepted:
            self._hides_unwanted_elements(page)

        page.wait_for_timeout(2000)
        return browser, page

    def _process_external_reference(self, external_reference):
        self.helper.log_info("Processing external reference....")
        if "url" not in external_reference:
            raise ValueError("No URL in this external reference, doing nothing")
        url_to_import = external_reference["url"].strip("/")
        # If the URL is a PDF file, just download it
        if self.import_as_pdf:
            try:
                if url_to_import.endswith(".pdf"):
                    # Download file
                    file_name = url_to_import.split("/")[-1]
                    req = urllib.request.Request(url_to_import, headers=self.headers)
                    response = urllib.request.urlopen(
                        req, context=ssl.create_default_context()
                    )
                    data = response.read()
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=file_name,
                        data=data,
                        mime_type="application/pdf",
                    )
                else:
                    file_name = url_to_import.split("/")[-1] + ".pdf"
                    with sync_playwright() as p:
                        browser, page = self._process_playwright(p, url_to_import)
                        page.pdf(
                            path="data.pdf",
                            format="A4",
                            margin={
                                "top": "10mm",
                                "bottom": "10mm",
                                "left": "15mm",
                                "right": "15mm",
                            },
                            scale=0.9,
                        )
                        browser.close()
                    with open("./data.pdf", "rb") as file:
                        data = file.read()
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=file_name,
                        data=data,
                        mime_type="application/pdf",
                    )
                    self.delete_files()
            except Exception as e:
                raise ValueError(e)
        if self.import_as_md:
            if url_to_import.endswith(".pdf") and self.import_pdf_as_md:
                try:
                    urllib.request.urlretrieve(url_to_import, "./data.pdf")
                    outfp = open("./data.html", "w", encoding="utf-8")
                    rsrcmgr = PDFResourceManager(caching=True)
                    device = HTMLConverter(
                        rsrcmgr,
                        outfp,
                        scale=1,
                        layoutmode="normal",
                        laparams=LAParams(),
                        imagewriter=None,
                        debug=False,
                    )
                    interpreter = PDFPageInterpreter(rsrcmgr, device)
                    with open("./data.pdf", "rb") as fp:
                        for page in PDFPage.get_pages(
                            fp,
                            set(),
                            maxpages=0,
                            password=b"",
                            caching=False,
                            check_extractable=True,
                        ):
                            page.rotate = (page.rotate + 0) % 360
                            interpreter.process_page(page)
                    device.close()
                    outfp.close()
                    with open("./data.html", "r") as file:
                        html = file.read().replace("\n", "")
                    file_name = url_to_import.split("/")[-1] + ".md"
                    text_maker = html2text.HTML2Text()
                    text_maker.ignore_links = False
                    text_maker.ignore_images = False
                    text_maker.ignore_tables = False
                    text_maker.ignore_emphasis = False
                    data = text_maker.handle(html)
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=file_name,
                        data=data,
                        mime_type="text/markdown",
                    )
                    self.delete_files()
                except Exception as e:
                    self.delete_files()
                    self.helper.log_error(e)
            else:
                try:
                    file_name = url_to_import.split("/")[-1] + ".md"
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
                    with sync_playwright() as p:
                        browser, page = self._process_playwright(p, url_to_import)
                        html = page.content()
                        browser.close()
                    data = text_maker.handle(html)
                    data = data.replace("](//", "](https://")
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=file_name,
                        data=data,
                        mime_type="text/markdown",
                    )
                except Exception as e:
                    self.helper.log_error(e)
        return "Import process is finished."

    def _process_message(self, data: Dict):
        external_reference = data["enrichment_entity"]
        self.helper.log_info(
            "External reference found: " + external_reference["source_name"]
        )
        return self._process_external_reference(external_reference)

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    externalReferenceInstance = ImportExternalReferenceConnector()
    externalReferenceInstance.start()
