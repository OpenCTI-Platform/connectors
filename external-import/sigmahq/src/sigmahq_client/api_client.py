import zipfile
from io import BytesIO
from typing import Any

import requests
from pycti import OpenCTIConnectorHelper


class SigmaHQClient:

    def __init__(self, helper: OpenCTIConnectorHelper):
        """
        :param helper:
        """
        self.helper = helper
        self.base_url = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"

        # Define headers in session and update when needed
        self.session = requests.Session()

    def get_lastest_published_version(self) -> dict[str, Any] | None:
        """
        :return:
        """
        try:
            response = self.session.get(self.base_url)
            response.raise_for_status()
            release = response.json()
            return {
                "tag": release["tag_name"],
                "name": release["name"],
                "url": release["url"],
                "published_at": release["published_at"],
                "assets": release["assets"],
            }
        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred while getting latest published version of SigmaHQ rule package",
                err,
            )

    def download_package(self, url):
        """
        :param url:
        :return:
        """
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.content
        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred while downloading latest SigmaHQ rule package", err
            )

    def download_and_convert_package(self, url):

        try:
            response = self.session.get(url, stream=True)
            response.raise_for_status()
            zip_content = BytesIO(response.content)
            sigma_rules = []
            with zipfile.ZipFile(zip_content) as zip_ref:
                for filename in zip_ref.namelist():
                    # ignore folder
                    if filename.endswith("/"):
                        continue
                    if filename.endswith(".yml"):
                        with zip_ref.open(filename) as file:
                            content = file.read()
                            rule = {
                                "filename": filename,
                                "rule_content": content.decode("utf-8"),
                            }
                            sigma_rules.append(rule)
            return sigma_rules
        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred while downloading latest SigmaHQ rule package", err
            )
