import yaml
import os
import urllib.request
import ssl
import certifi
import pdfkit
import html2text

from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import HTMLConverter
from pdfminer.layout import LAParams
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

    def _process_external_reference(self, external_reference):
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
                        req, context=ssl.create_default_context(cafile=certifi.where())
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
                    options = {"javascript-delay": 10000, "no-stop-slow-scripts": None}
                    data = pdfkit.from_url(url_to_import, False, options=options)
                    self.helper.api.external_reference.add_file(
                        id=external_reference["id"],
                        file_name=file_name,
                        data=data,
                        mime_type="application/pdf",
                    )
            except Exception as e:
                self.helper.log_error(e)
        if self.import_as_md:
            if url_to_import.endswith(".pdf") and self.import_pdf_as_md:
                try:
                    req = urllib.request.Request(url_to_import, headers=self.headers)
                    response = urllib.request.urlopen(
                        req, context=ssl.create_default_context(cafile=certifi.where())
                    )
                    f = open("./data.pdf", "w")
                    content = response.read()
                    f.write(content)
                    f.close()
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
                    req = urllib.request.Request(url_to_import, headers=self.headers)
                    response = urllib.request.urlopen(
                        req, context=ssl.create_default_context(cafile=certifi.where())
                    )
                    html = response.read().decode("utf-8")
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

    def _process_message(self, data):
        entity_id = data["entity_id"]
        external_reference = self.helper.api.external_reference.read(id=entity_id)
        return self._process_external_reference(external_reference)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    externalReferenceInstance = ImportExternalReferenceConnector()
    externalReferenceInstance.start()
