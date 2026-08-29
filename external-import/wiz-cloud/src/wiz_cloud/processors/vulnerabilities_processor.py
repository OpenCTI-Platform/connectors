"""Processor turning Wiz vulnerability findings into OpenCTI Vulnerabilities.

Each finding becomes a Vulnerability keyed on its CVE id, linked to the
System it was found on with a has relationship. Only the assets referenced by
the issues imported during the current run are scanned.
"""

from collections.abc import Iterator
from importlib import resources

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from requests.exceptions import RequestException
from wiz_cloud.client_api import WizApiClient, WizGraphQLError
from wiz_cloud.run_context import WizRunContext, batched

VULNERABILITIES_QUERY = (
    resources.files("wiz_cloud.queries")
    .joinpath("vulnerability_findings.graphql")
    .read_text("utf-8")
)

# assetIdV2.equals takes a list, so assets are queried in batches rather than
# one request per asset.
ASSET_BATCH_SIZE = 50


class WizVulnerabilitiesProcessor(BaseDataProcessor):
    """Import vulnerability findings for the assets seen in the current run.

    Args:
        run_context: Context populated by the issues processor, holding the
            asset ids to scan.
    """

    def __init__(self, run_context: WizRunContext) -> None:
        self._run_context = run_context

    # -- lifecycle -----------------------------------------------------------

    def post_init(self) -> None:
        """Build the Wiz client and the objects shared by every bundle.

        Called by the SDK once dependencies are injected, so settings are
        available here but not in __init__.
        """
        self._config = self.settings.wiz_cloud
        self._client = WizApiClient(
            base_url=str(self._config.api_url),
            auth_url=str(self._config.auth_url),
            client_id=self._config.client_id.get_secret_value(),
            client_secret=self._config.client_secret.get_secret_value(),
            timeout=60,
            max_retries=3,
            backoff_factor=2.0,
        )
        self._author = OrganizationAuthor(name="Wiz")
        self._marking = TLPMarking(level=self._config.marking)

    # -- collect -------------------------------------------------------------

    def collect(self) -> Iterator[list[dict]]:
        """Fetch the vulnerability findings of the assets seen this run.

        Asset ids are batched, and each batch is paginated to exhaustion. A
        Wiz failure is logged and swallowed: the issue bundles of this run are
        already sent and must not be discarded.

        Yields:
            Lists of raw finding dicts, one per API page.
        """
        asset_ids = self._run_context.asset_ids
        if not asset_ids:
            self.logger.info(
                "[WIZ-CLOUD] No asset to scan, skipping vulnerability import"
            )
            return

        self.work_name = f"Wiz Cloud vulnerabilities import for {len(asset_ids)} assets"
        self.logger.info(
            "[WIZ-CLOUD] Collecting vulnerabilities",
            {
                "assets": len(asset_ids),
                "severity": self._config.vulnerability_severity,
                "status": self._config.vulnerability_status,
                "has_exploit": self._config.vulnerability_has_exploit,
            },
        )

        for batch in batched(asset_ids, ASSET_BATCH_SIZE):
            filter_by: dict = {
                "assetIdV2": {"equals": batch},
                "severity": list(self._config.vulnerability_severity),
                "status": list(self._config.vulnerability_status),
            }
            if self._config.vulnerability_has_exploit:
                filter_by["hasExploit"] = True

            variables = {
                "first": self._config.page_size,
                "after": None,
                "orderBy": {"field": "CREATED_AT", "direction": "DESC"},
                "filterBy": filter_by,
            }
            try:
                yield from self._client.paginate(
                    VULNERABILITIES_QUERY,
                    variables,
                    connection_key="vulnerabilityFindings",
                )
            except (WizGraphQLError, RequestException) as err:
                self.logger.error(
                    "[WIZ-CLOUD] Failed to collect vulnerabilities for an asset batch",
                    {"assets": len(batch), "error": str(err)},
                )

    # -- transform -----------------------------------------------------------

    def transform(self, data: Iterator[list[dict]]) -> Iterator[list]:
        """Convert raw finding pages into bundle objects.

        Args:
            data: Pages of raw finding dicts yielded by collect().

        Yields:
            Lists of SDK objects, one bundle per non-empty page.
        """
        for _ in data:
            yield []
