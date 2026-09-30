"""Processor that imports Wiz Threat Detection issues as OpenCTI Incidents.

Each issue becomes an Incident. The cloud asset of the issue becomes a
System, with a "targets" relationship from the Incident to the System.

When vulnerability import is enabled, collect() also gets the vulnerability
findings of this asset. transform() puts them in the same bundle as the
issue, so the issue and its vulnerabilities are always sent together.

If a call to Wiz fails, the run stops. This includes a pydantic
ValidationError when the client cannot parse an issue or a finding. The
cursor is not updated, so the next run imports the same issues again.
Only one case is skipped instead: a finding that the OCTI Vulnerability
model rejects during conversion.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import OrganizationAuthor, System, TLPMarking
from pydantic import ValidationError
from wiz_client.client_api import WizApiClient
from wiz_cloud.processors.issues_processor.converters import (
    IssueConverter,
    VulnerabilityConverter,
)

if TYPE_CHECKING:
    from wiz_client.models import WizIssue, WizVulnerabilityFinding
    from wiz_cloud.settings import ConnectorSettings
    from wiz_cloud.state import WizConnectorState


class WizIssuesProcessor(BaseDataProcessor):
    settings: ConnectorSettings
    state: WizConnectorState

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
            logger=self.logger,
            timeout=60,
            max_retries=3,
            backoff_factor=2.0,
        )

        self._author = OrganizationAuthor(name="Wiz")
        self._marking = TLPMarking(level=self._config.marking)

        self._issue_converter = IssueConverter(
            author=self._author,
            marking=self._marking,
        )
        self._vulnerability_converter = VulnerabilityConverter(
            author=self._author,
            marking=self._marking,
        )

    def _paginate_issues(self, since: datetime) -> Iterator[list[WizIssue]]:
        """Get the Threat Detection issues created after `since`, page by page.

        The client returns the oldest issues first. See state.py for why
        this keeps the cursor correct.

        Args:
            since: Only issues created after this date are returned.

        Returns:
            Pages of parsed issues.
        """
        return self._client.paginate_issues(
            first=self._config.page_size,
            after=None,
            type=["THREAT_DETECTION"],
            severity=self._config.issue_severity,
            status=self._config.issue_status,
            created_after=since,
        )

    def _paginate_vulnerabilities_findings(
        self, issue: WizIssue
    ) -> Iterator[list[WizVulnerabilityFinding]]:
        """Get the vulnerability findings of the asset of an issue, page by page.

        Args:
            issue: The issue. Its entitySnapshot is the asset to query.

        Returns:
            Pages of parsed findings. No pages if the issue has no asset.
        """
        if not issue.entity_snapshot:
            return iter([])

        return self._client.paginate_vulnerabilities_findings(
            first=self._config.page_size,
            after=None,
            severity=self._config.vulnerability_severity,
            status=self._config.vulnerability_status,
            # Send None, not False, when the option is off.
            # `hasExploit: false` returns only findings WITHOUT a known exploit.
            has_exploit=self._config.vulnerability_has_exploit or None,
            asset_id=issue.entity_snapshot.id,
        )

    def collect(self) -> Iterator[list[dict]]:
        """Get the Threat Detection issues created since the last run.

        The start date is the cursor saved in the state. On the first run,
        it is now minus the `since` setting.

        When vulnerability import is enabled, the findings of each issue's
        asset are also fetched. Each asset is queried only once per run:
        many issues can share the same asset, and its findings convert to
        deterministic ids, so a second query would only send the same
        objects again. Other issues on this asset get an empty list of
        findings.

        Yields:
            One list for each page of issues. The list has one dict per
            issue, with two keys:
            - "issue": the parsed issue.
            - "vulnerabilities": the parsed findings of its asset.

        Raises:
            pydantic.ValidationError: If the client cannot parse an issue or
                a finding. The run stops on purpose.
        """
        since = self.state.issues_last_created_at or (
            datetime.now(tz=timezone.utc) - self._config.since
        )

        self.work_name = f"Wiz Cloud issues import since {since:%Y-%m-%d %H:%M}"

        self.logger.info(
            "[WIZ-CLOUD] Collecting issues",
            {
                "since": since.isoformat(),
                "severity": self._config.issue_severity,
                "status": self._config.issue_status,
            },
        )

        # IDs of the assets already queried during this run.
        scanned_assets: set[str] = set()

        for issues_page in self._paginate_issues(since=since):
            results = []

            for issue in issues_page:
                result = {"issue": issue, "vulnerabilities": []}

                if self._config.import_vulnerabilities and issue.entity_snapshot:
                    asset_id = issue.entity_snapshot.id
                    if asset_id in scanned_assets:
                        self.logger.debug(
                            "[WIZ-CLOUD] Asset already scanned this run, skipping",
                            {"issue_id": issue.id, "asset_id": asset_id},
                        )
                    else:
                        scanned_assets.add(asset_id)
                        for findings_page in self._paginate_vulnerabilities_findings(
                            issue=issue
                        ):
                            result["vulnerabilities"].extend(findings_page)

                results.append(result)

            yield results

    def transform(self, data: Iterator[list[dict]]) -> Iterator[list]:
        """Convert the results from collect() into bundles of OpenCTI objects.

        Each page gives one bundle, if it is not empty. For each issue, the
        bundle has the Incident, the System and the "targets" relationship.
        When vulnerability import is enabled, it also has the Vulnerabilities
        of the System and their "has" relationships.

        These findings are skipped and logged, and the rest of the page is
        kept:
        - a finding without a CVE id;
        - a finding that the OCTI Vulnerability model rejects.

        Args:
            data: Results from collect().

        Yields:
            Lists of OCTI objects, one per page that is not empty. The author
            and the marking are added at the start of the first list only.
        """
        # Run-scoped cache: the same entitySnapshot backs many issues
        systems_cache: dict[str, System] = {}
        issues_converted = 0
        vulnerabilities_converted = 0
        bundles_sent = 0
        max_created = self.state.issues_last_created_at

        for results in data:
            page_objects: list = []

            for result in results:
                issue_objects, issue_vulnerabilities_count = self._convert_result(
                    result, systems_cache
                )
                page_objects.extend(issue_objects)
                issues_converted += 1
                vulnerabilities_converted += issue_vulnerabilities_count

                created_at = result["issue"].created_at
                if max_created is None or created_at > max_created:
                    max_created = created_at

            if page_objects:
                yield self._with_shared(page_objects, already_sent=bundles_sent > 0)
                bundles_sent += 1

        if issues_converted == 0:
            self.logger.info(
                "[WIZ-CLOUD] Nothing to ingest, no new issue since the last run",
                (
                    {"since": self.state.issues_last_created_at}
                    if self.state.issues_last_created_at
                    else {}
                ),
            )
        else:
            self.logger.info(
                "[WIZ-CLOUD] Import finished",
                {
                    "incidents": issues_converted,
                    "vulnerabilities": vulnerabilities_converted,
                    "bundles": bundles_sent,
                },
            )

        self._advance_cursor(max_created)

    def _convert_result(
        self, result: dict, systems_cache: dict[str, System]
    ) -> tuple[list, int]:
        """Convert one issue and the vulnerability findings of its asset.

        Args:
            result: One item of a collect() page.
            systems_cache: Systems already created during this run.

        Returns:
            The objects of the issue followed by the objects of its findings,
            and the number of findings converted.
        """
        issue: WizIssue = result["issue"]
        objects = self._issue_converter.convert_issue(issue, systems_cache)

        vulnerabilities_count = 0
        if self._config.import_vulnerabilities and issue.entity_snapshot:
            system = systems_cache[issue.entity_snapshot.id]
            for finding in result["vulnerabilities"]:
                finding_objects = self._convert_finding(finding, system)
                if finding_objects:
                    objects.extend(finding_objects)
                    vulnerabilities_count += 1

        self.logger.info(
            "[WIZ-CLOUD] Sending an incident with its vulnerabilities",
            {
                "issue_id": issue.id,
                "asset": issue.entity_snapshot.name if issue.entity_snapshot else None,
                # Zero when the asset was already scanned this run:
                # its vulnerabilities went out with an earlier issue.
                "vulnerabilities": vulnerabilities_count,
            },
        )
        return objects, vulnerabilities_count

    def _convert_finding(
        self, finding: WizVulnerabilityFinding, system: System
    ) -> list:
        """Convert one vulnerability finding, or skip it.

        Args:
            finding: The parsed finding.
            system: The System of the asset of the finding.

        Returns:
            The Vulnerability and its "has" relationship. An empty list if the
            finding has no CVE id or if the OCTI Vulnerability model rejects it.
        """
        if not finding.name:
            self.logger.warning(
                "[WIZ-CLOUD] Vulnerability finding without CVE id, skipping",
                {"id": finding.id},
            )
            return []
        try:
            return self._vulnerability_converter.convert_vulnerability(finding, system)
        except ValidationError as err:
            # Skip only this finding. The incident and the other findings are
            # still sent.
            self.logger.warning(
                "[WIZ-CLOUD] Vulnerability finding conversion error, skipping",
                {"id": finding.id, "error": str(err)},
            )
            return []

    def _with_shared(self, objects: list, already_sent: bool) -> list:
        """Prepend the author and marking to the first bundle carrying data.

        Args:
            objects: The bundle objects.
            already_sent: Whether a previous bundle carried them.

        Returns:
            The bundle, with author and marking in front when they are still
            owed. They never travel in a bundle of their own.
        """
        if already_sent:
            return objects
        return [self._author, self._marking, *objects]

    def _advance_cursor(self, max_created: datetime | None) -> None:
        """Save the createdAt of the newest issue of this run in the state.

        This method runs only when all pages were fetched and converted. If
        a call to Wiz fails, collect() raises an error first, so the cursor
        is not updated and the next run imports the same issues again.

        The connector saves the state only when all processors succeed.

        Args:
            max_created: The newest createdAt of this run, or None.
        """
        if max_created is not None:
            self.state.issues_last_created_at = max_created
