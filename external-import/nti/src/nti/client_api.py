import gzip
import json
import traceback
from zipfile import ZipFile
from io import BytesIO
from urllib.request import urlopen, Request

class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        # construct header
        self.headers = {
            "Accept-encoding": "gzip",
            "Accept": "application/json",
            "X-Ns-Nti-Key": self.config.ns_nti_key,
        }
        self.nti_base_url = self.config.nti_base_url
        # type of feed package (updated or full)
        self.package_type = self.config.package_type


    def acquire_feed_packages(self, create_tasks: list) -> list:
        """
        Downloading and unzipping a .zip file without writing to disk

        :return: intelligence_data
        """
        feed_url = self.nti_base_url + "download/feed/?type=" + self.package_type
        try:
            req = Request(feed_url, headers=self.headers)
            with urlopen(req) as response:
                encoding = response.headers.get('Content-Encoding')
                raw_data = response.read()
            if encoding == 'gzip':
                # unzip gzip
                with gzip.GzipFile(fileobj=BytesIO(raw_data)) as gz:
                    raw_data = gz.read()
            # unzip ZIP file
            with ZipFile(BytesIO(raw_data)) as myzip:
                # filename: 'data.NTI.API.V2.0.ioc-updated.20250425.0001.json'
                for filename in myzip.namelist():
                    # if create task set to true
                    current_task = filename.rsplit('.', 3)[0]
                    # create_tasks: 'data.NTI.API.V2.0.ioc-updated'
                    if current_task in create_tasks:
                        self.helper.connector_logger.info(
                            f"[CLIENT] acquiring {filename}.",
                        )
                        intelligence_data = []
                        with myzip.open(filename,"r") as f:
                            # skip header
                            f.readline()
                            for line in f:
                                intelligence_data.append(json.loads(line.strip()))
                        yield intelligence_data, current_task
        except Exception:
            self.helper.connector_logger.info(
                "[CLIENT] acquire feed packages error.",
                {"Error message": traceback.format_exc()}
            )
            raise
