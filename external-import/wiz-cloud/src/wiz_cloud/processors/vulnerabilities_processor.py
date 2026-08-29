"""Processor turning Wiz vulnerability findings into OpenCTI Vulnerabilities.

Each finding becomes a Vulnerability keyed on its CVE id, linked to the
System it was found on with a has relationship. Only the assets referenced by
the issues imported during the current run are scanned.
"""

from collections.abc import Iterator
from importlib import resources

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    ExternalReference,
    OrganizationAuthor,
    Relationship,
    System,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.enums import CvssSeverity, RelationshipType
from pydantic import ValidationError
from requests.exceptions import RequestException
from wiz_cloud.client_api import WizApiClient, WizGraphQLError
from wiz_cloud.models import WizVulnerabilityFinding, WizVulnerableAsset
from wiz_cloud.run_context import WizRunContext, batched

VULNERABILITIES_QUERY = (
    resources.files("wiz_cloud.queries")
    .joinpath("vulnerability_findings.graphql")
    .read_text("utf-8")
)

# assetIdV2.equals takes a list, so assets are queried in batches rather than
# one request per asset.
ASSET_BATCH_SIZE = 50


def _ratio(percentage: float | None) -> float | None:
    """Convert a Wiz percentage into the 0-1 ratio OpenCTI expects.

    Args:
        percentage: A percentage such as 72.4, or None.

    Returns:
        The value divided by 100, or None. Values outside 0-100 are dropped
        rather than rejected by the model.
    """
    if percentage is None or not 0 <= percentage <= 100:
        return None
    return round(percentage / 100, 6)


def _user_interaction(required: bool | None) -> str | None:
    """Convert the Wiz boolean into the CVSS user-interaction string.

    Args:
        required: Whether user interaction is required, or None.

    Returns:
        "REQUIRED", "NONE", or None when unknown.
    """
    if required is None:
        return None
    return "REQUIRED" if required else "NONE"


def _cvss_severity(severity: str | None) -> CvssSeverity | None:
    """Convert a Wiz CVSS severity into the SDK enum.

    Args:
        severity: A Wiz severity such as "HIGH", or None.

    Returns:
        The matching CvssSeverity, or None when it is unknown.
    """
    if not severity:
        return None
    try:
        return CvssSeverity(severity.upper())
    except ValueError:
        return None


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

        Unparseable findings are logged and skipped rather than failing the
        run, so one bad node cannot sink a whole page.

        Args:
            data: Pages of raw finding dicts yielded by collect().

        Yields:
            Lists of SDK objects, one bundle per non-empty page.
        """
        # Run-scoped caches: an asset carries hundreds of findings, and
        # author/marking must be sent once, not once per page.
        systems_cache: dict[str, System] = {}
        shared_sent = False

        for page in data:
            objects: list = []

            for raw in page:
                try:
                    finding = WizVulnerabilityFinding.model_validate(raw)
                except ValidationError as err:
                    self.logger.warning(
                        "[WIZ-CLOUD] Skipping unparseable vulnerability finding",
                        {"id": raw.get("id"), "error": str(err)},
                    )
                    continue

                objects.extend(self._convert(finding, systems_cache))

            if not objects:
                continue

            # Author and marking ride along with the first bundle that
            # actually carries vulnerabilities, never on their own.
            if not shared_sent:
                objects = [self._author, self._marking, *objects]
                shared_sent = True

            yield objects

    # -- conversion ----------------------------------------------------------

    def _convert(
        self, finding: WizVulnerabilityFinding, systems_cache: dict[str, System]
    ) -> list:
        """Convert one finding into its bundle objects.

        Args:
            finding: Parsed Wiz vulnerability finding.
            systems_cache: Systems already built during this run, keyed by
                asset id, so an asset carrying hundreds of findings is emitted
                once.

        Returns:
            The Vulnerability, the has Relationship, and the System when it
            was not emitted yet. An empty list when the finding carries no CVE
            id or no asset, since neither can be linked.
        """
        if not finding.name or finding.vulnerable_asset is None:
            self.logger.warning(
                "[WIZ-CLOUD] Skipping finding without a CVE id or an asset",
                {"id": finding.id},
            )
            return []

        objects: list = []
        vulnerability = self._vulnerability(finding)
        objects.append(vulnerability)

        system, is_new = self._system_for(finding.vulnerable_asset, systems_cache)
        if is_new:
            objects.append(system)

        objects.append(
            Relationship(
                type=RelationshipType.HAS,
                source=system,
                target=vulnerability,
                description=(
                    f"Wiz finding {finding.id}, "
                    f"severity {finding.severity}, status {finding.status}"
                ),
                start_time=finding.first_detected_at,
                # stop_time is left unset on purpose: generate_id() hashes it,
                # so lastDetectedAt would mint a new relationship every run.
                author=self._author,
                markings=[self._marking],
            )
        )
        return objects

    def _vulnerability(self, finding: WizVulnerabilityFinding) -> Vulnerability:
        cvss_v2 = finding.cvss_v2
        cvss_v3 = finding.cvss_v3
        cvss_v4 = finding.cvss_v4
        return Vulnerability(
            # The OpenCTI id derives from the name alone, so it must be the
            # CVE id.
            name=finding.name,
            # CVEDescription is the CVE text; description is finding-specific
            # prose that would differ per asset and fight itself on merge.
            description=finding.cve_description or finding.description or None,
            # Wiz score is a CVSS base score, not the OpenCTI 0-100 score.
            cvss_v3_base_score=finding.score,
            cvss_v3_base_severity=_cvss_severity(finding.cvss_severity),
            cvss_v3_attack_vector=cvss_v3.attack_vector if cvss_v3 else None,
            cvss_v3_attack_complexity=cvss_v3.attack_complexity if cvss_v3 else None,
            cvss_v3_privileges_required=(
                cvss_v3.privileges_required if cvss_v3 else None
            ),
            cvss_v3_user_interaction=(
                _user_interaction(cvss_v3.user_interaction_required)
                if cvss_v3
                else None
            ),
            cvss_v3_confidentiality_impact=(
                cvss_v3.confidentiality_impact if cvss_v3 else None
            ),
            cvss_v3_integrity_impact=cvss_v3.integrity_impact if cvss_v3 else None,
            cvss_v3_availability_impact=(
                cvss_v3.availability_impact if cvss_v3 else None
            ),
            cvss_v3_scope=cvss_v3.scope if cvss_v3 else None,
            cvss_v3_exploit_code_maturity=(
                cvss_v3.exploit_code_maturity if cvss_v3 else None
            ),
            cvss_v2_access_vector=cvss_v2.attack_vector if cvss_v2 else None,
            cvss_v2_access_complexity=cvss_v2.attack_complexity if cvss_v2 else None,
            cvss_v2_confidentiality_impact=(
                cvss_v2.confidentiality_impact if cvss_v2 else None
            ),
            cvss_v2_integrity_impact=cvss_v2.integrity_impact if cvss_v2 else None,
            cvss_v2_availability_impact=(
                cvss_v2.availability_impact if cvss_v2 else None
            ),
            cvss_v4_attack_vector=cvss_v4.attack_vector if cvss_v4 else None,
            cvss_v4_attack_complexity=cvss_v4.attack_complexity if cvss_v4 else None,
            cvss_v4_attack_requirements=(
                cvss_v4.attack_requirements if cvss_v4 else None
            ),
            cvss_v4_privileges_required=(
                cvss_v4.privileges_required if cvss_v4 else None
            ),
            cvss_v4_user_interaction=cvss_v4.user_interaction if cvss_v4 else None,
            epss_score=_ratio(finding.epss_probability),
            epss_percentile=_ratio(finding.epss_percentile),
            is_cisa_kev=finding.has_cisa_kev_exploit,
            external_references=self._finding_references(finding),
            author=self._author,
            markings=[self._marking],
        )

    def _finding_references(
        self, finding: WizVulnerabilityFinding
    ) -> list[ExternalReference]:
        references = []
        if finding.portal_url:
            references.append(
                ExternalReference(
                    source_name="Wiz",
                    url=finding.portal_url,  # taken from the API, never rebuilt
                    external_id=finding.id,
                    description="Wiz vulnerability finding",
                )
            )
        return references

    def _system_for(
        self, asset: WizVulnerableAsset, cache: dict[str, System]
    ) -> tuple[System, bool]:
        # The name matches the issue entitySnapshot name, so this System
        # resolves to the entity the issues processor already created.
        if asset.id in cache:
            return cache[asset.id], False

        description_parts = [
            part
            for part in (
                asset.type,
                asset.cloud_platform,
                asset.region or None,  # "" observed in payloads
                asset.provider_unique_id or None,
            )
            if part
        ]
        system = System(
            name=asset.name,
            description=" | ".join(description_parts) or None,
            labels=[f"{key}={value}" for key, value in asset.tags.items()],
            author=self._author,
            markings=[self._marking],
        )
        cache[asset.id] = system
        return system, True
