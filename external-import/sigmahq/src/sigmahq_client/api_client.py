import zipfile
from io import BytesIO
from typing import Any

import requests
from pycti import OpenCTIConnectorHelper

# Per-request timeouts (connect, read) for every GitHub call. ``Session.get``
# without ``timeout`` would hang the connector indefinitely on a stalled
# GitHub endpoint, blocking the OpenCTI scheduler. The connect budget is
# tight (5 s) — GitHub's edge resolves almost instantly when it can — and
# the read budget is generous (120 s) because the release ZIP can be
# several megabytes.
_HTTP_TIMEOUT_SECONDS: tuple[float, float] = (5.0, 120.0)

# GitHub explicitly recommends sending an ``Accept`` header that pins the
# REST API version and a descriptive ``User-Agent`` so requests can be
# attributed back to the integration on the GitHub side (and so we are
# not silently moved to the anonymous rate-limit bucket). See
# https://docs.github.com/en/rest/overview/resources-in-the-rest-api.
# ``X-GitHub-Api-Version`` opts us in to a specific, stable API surface
# rather than whichever version GitHub happens to default to.
_GITHUB_API_HEADERS: dict[str, str] = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "opencti-connector-sigmahq",
}


class SigmaHQClient:

    def __init__(self, helper: OpenCTIConnectorHelper):
        """
        :param helper:
        """
        self.helper = helper
        self.base_url = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"

        # Reuse a single ``requests.Session`` so TCP connections are pooled
        # across the metadata call + the release-asset download. Headers
        # are set once on the session and merged into every outgoing
        # request; per-call overrides can still be passed to ``get``.
        self.session = requests.Session()
        self.session.headers.update(_GITHUB_API_HEADERS)

    def get_latest_published_version(self) -> dict[str, Any] | None:
        """Return the latest SigmaHQ release metadata, or ``None`` on failure.

        Returning ``None`` (rather than raising) lets the caller surface a
        graceful "nothing to do" log line when GitHub is unreachable or rate
        limited, instead of crashing the connector run.
        """
        try:
            response = self.session.get(self.base_url, timeout=_HTTP_TIMEOUT_SECONDS)
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

    def download_and_convert_package(self, url: str) -> list[dict[str, str]]:
        """Download and unzip the rule package.

        Always returns a list so the caller can iterate without a ``None``
        guard. On failure we log the error and return an empty list, which
        the connector treats as "no rules to ingest this run".
        """
        try:
            # ``zipfile.ZipFile`` needs a seekable buffer, and we ultimately
            # read the entire archive into memory below — so ``stream=True``
            # (which would force us to also iterate ``response.iter_content``
            # to materialise the bytes) buys nothing and only complicates
            # the error path. A plain buffered ``GET`` is both simpler and
            # equivalent on peak memory.
            response = self.session.get(url, timeout=_HTTP_TIMEOUT_SECONDS)
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
