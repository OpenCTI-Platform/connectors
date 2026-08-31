"""Vulnerability findings fetched for the asset of a single issue.

Despite its name, which follows the file naming of this package, this is a
collaborator of the issues processor rather than a ``BaseDataProcessor``
registered with the SDK: an issue and the vulnerabilities of the resource it
was raised on are converted together and sent in the same bundle, so the two
can never be committed apart.

Each finding becomes a Vulnerability keyed on its CVE id, linked with a has
relationship to the System the issue already built for that asset.
"""

from importlib import resources

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
from wiz_cloud.models import WizVulnerabilityFinding
from wiz_cloud.settings import WizCloudConfig

VULNERABILITIES_QUERY = (
    resources.files("wiz_cloud.queries")
    .joinpath("vulnerability_findings.graphql")
    .read_text("utf-8")
)


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


class WizVulnerabilityFetcher:
    """Fetch and convert the vulnerabilities of one asset at a time.

    Args:
        client: Wiz API client, shared with the issues processor so a single
            access token serves both queries.
        config: The connector configuration.
        logger: The connector logger.
        author: Author attached to every emitted object.
        marking: Marking attached to every emitted object.
    """

    def __init__(
        self,
        client: WizApiClient,
        config: WizCloudConfig,
        logger,
        author: OrganizationAuthor,
        marking: TLPMarking,
    ) -> None:
        self._client = client
        self._config = config
        self._logger = logger
        self._author = author
        self._marking = marking
        # Assets already queried during this run. The same resource backs
        # several issues, and findings convert to deterministic ids, so
        # querying it twice would send byte-identical objects for nothing.
        self._seen_assets: set[str] = set()
        self.failures = 0

    def objects_for_asset(self, asset_id: str, system: System) -> list:
        """Convert every vulnerability of one asset into bundle objects.

        A Wiz failure is logged and counted rather than raised: the issue this
        asset belongs to is still worth importing. The count is what tells the
        issues processor to hold the cursor back, so the window is replayed on
        the next run instead of being silently skipped.

        Args:
            asset_id: The entitySnapshot id of the cloud resource.
            system: The System the issues processor built for that asset, so
                the relationship points at the very object in the bundle.

        Returns:
            Vulnerabilities and their has relationships. Empty when the asset
            was already queried this run, carries no finding, or failed.
        """
        if asset_id in self._seen_assets:
            return []
        self._seen_assets.add(asset_id)

        objects: list = []
        try:
            for page in self._client.paginate(
                VULNERABILITIES_QUERY,
                self._variables(asset_id),
                connection_key="vulnerabilityFindings",
            ):
                for raw in page:
                    try:
                        finding = WizVulnerabilityFinding.model_validate(raw)
                    except ValidationError as err:
                        self._logger.warning(
                            "[WIZ-CLOUD] Skipping unparseable vulnerability finding",
                            {"id": raw.get("id"), "error": str(err)},
                        )
                        continue
                    objects.extend(self._convert(finding, system))
        except (WizGraphQLError, RequestException) as err:
            self.failures += 1
            self._logger.error(
                "[WIZ-CLOUD] Failed to collect vulnerabilities for an asset",
                {"asset_id": asset_id, "error": str(err)},
            )
            # Partial objects are dropped: half an asset is worse than none,
            # and the run will be replayed anyway.
            return []

        return objects

    def _variables(self, asset_id: str) -> dict:
        filter_by: dict = {
            "assetIdV2": {"equals": [asset_id]},
            "severity": list(self._config.vulnerability_severity),
            "status": list(self._config.vulnerability_status),
        }
        if self._config.vulnerability_has_exploit:
            filter_by["hasExploit"] = True
        return {
            "first": self._config.page_size,
            "after": None,
            "orderBy": {"field": "CREATED_AT", "direction": "DESC"},
            "filterBy": filter_by,
        }

    # -- conversion ----------------------------------------------------------

    def _convert(self, finding: WizVulnerabilityFinding, system: System) -> list:
        """Convert one finding into its bundle objects.

        Args:
            finding: Parsed Wiz vulnerability finding.
            system: The System carrying the vulnerability.

        Returns:
            The Vulnerability and its has Relationship, or an empty list when
            the finding carries no CVE id and so cannot be keyed.
        """
        if not finding.name:
            self._logger.warning(
                "[WIZ-CLOUD] Skipping finding without a CVE id",
                {"id": finding.id},
            )
            return []

        vulnerability = self._vulnerability(finding)
        return [
            vulnerability,
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
            ),
        ]

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
