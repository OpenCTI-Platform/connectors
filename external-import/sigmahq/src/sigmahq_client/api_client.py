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

    def get_latest_published_version(self) -> dict[str, Any] | None:
        """Return the latest SigmaHQ release metadata, or ``None`` on failure.

        Returning ``None`` (rather than raising) lets the caller surface a
        graceful "nothing to do" log line when GitHub is unreachable or rate
        limited, instead of crashing the connector run.
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
            # ``connector_logger.error`` expects a metadata dict as its second
            # positional argument; passing the raw exception object can break
            # structured logging. We log the message + a serialisable error
            # field, and emit the stack trace via ``exc_info`` for debugging.
            self.helper.connector_logger.error(
                "An error occurred while getting latest published version of SigmaHQ rule package",
                {"error": str(err)},
                exc_info=True,
            )
            return None

    def download_package(self, url: str) -> bytes | None:
        """Download the rule package, returning ``None`` on failure."""
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.content
        except Exception as err:
            self.helper.connector_logger.error(
                "An error occurred while downloading latest SigmaHQ rule package",
                {"error": str(err)},
                exc_info=True,
            )
            return None

    def download_and_convert_package(self, url: str) -> list[dict[str, str]]:
        """Download and unzip the rule package.

        Always returns a list so the caller can iterate without a ``None``
        guard. On failure we log the error and return an empty list, which
        the connector treats as "no rules to ingest this run".
        """
        try:
            response = self.session.get(url, stream=True)
            response.raise_for_status()
            zip_content = BytesIO(response.content)
            sigma_rules: list[dict[str, str]] = []
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
                "An error occurred while downloading latest SigmaHQ rule package",
                {"error": str(err)},
                exc_info=True,
            )
            return []
