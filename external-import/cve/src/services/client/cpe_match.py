from datetime import datetime, timezone

from src.services.client.api import CVEClient

CPE_MATCH_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"


class CPEMatchClient(CVEClient):
    """Async client for the NVD CPE Match API.

    Resolves CPE names associated with a given CVE ID.
    API documentation: https://nvd.nist.gov/developers/products
    """

    async def get_cpes_for_cve(
        self, cve_id: str, modified_since: datetime | None = None
    ) -> list[str]:
        """Retrieve all unique CPE names associated with a CVE.

        Calls the NVD CPE Match API with the given CVE ID, handles pagination,
        and returns a deduplicated list of CPE Name strings.

        The NVD CPE Match API answers HTTP 500 when `cveId` is combined with
        `lastModStartDate`/`lastModEndDate`, so only `cveId` is sent and the
        `modified_since` window is applied here, on the response.

        Args:
            cve_id: The CVE identifier (e.g. "CVE-2022-32223").
            modified_since: When set, match strings whose more recent of
                `lastModified` and `cpeLastModified` is before this datetime
                are ignored. Naive datetimes are treated as UTC.

        Returns:
            A deduplicated list of CPE Name strings (format cpe:2.3:...).
        """
        cpe_names: set[str] = set()
        params: dict = {"cveId": cve_id}

        self.helper.connector_logger.debug(
            "[CPE MATCH API] Fetching CPE matches", meta={"cve_id": cve_id}
        )

        try:
            data = await self.get_complete_collection(CPE_MATCH_BASE_URL, params)
            if data is None:
                self.helper.connector_logger.warning(
                    "[CPE MATCH API] No response, skipping CPE resolution",
                    meta={"cve_id": cve_id, "error": self._last_error},
                )
                return []

            self._extract_cpe_names(data, cpe_names, modified_since)

            # Handle pagination
            total_results = data.get("totalResults", 0)
            results_per_page = data.get("resultsPerPage", 0)

            if not isinstance(results_per_page, int) or results_per_page <= 0:
                if total_results:
                    self.helper.connector_logger.warning(
                        "[CPE MATCH API] Unexpected resultsPerPage, "
                        "stopping pagination to avoid infinite loop",
                        meta={
                            "cve_id": cve_id,
                            "results_per_page": results_per_page,
                        },
                    )
                return list(cpe_names)

            start_index = results_per_page

            while start_index < total_results:
                paginated_params = {
                    **params,
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                }
                page_data = await self.get_complete_collection(
                    CPE_MATCH_BASE_URL, paginated_params
                )
                if page_data is None:
                    self.helper.connector_logger.warning(
                        "[CPE MATCH API] No response for a later page, "
                        "keeping the CPEs already collected",
                        meta={
                            "cve_id": cve_id,
                            "start_index": start_index,
                            "error": self._last_error,
                        },
                    )
                    break
                self._extract_cpe_names(page_data, cpe_names, modified_since)
                results_per_page = page_data.get("resultsPerPage", 0)
                if not isinstance(results_per_page, int) or results_per_page <= 0:
                    self.helper.connector_logger.warning(
                        "[CPE MATCH API] Unexpected page resultsPerPage, "
                        "stopping pagination to avoid infinite loop",
                        meta={
                            "cve_id": cve_id,
                            "results_per_page": results_per_page,
                            "start_index": start_index,
                        },
                    )
                    break
                start_index += results_per_page

            self.helper.connector_logger.debug(
                "[CPE MATCH API] Found unique CPEs",
                meta={"cve_id": cve_id, "count": len(cpe_names)},
            )

        except Exception as err:
            self.helper.connector_logger.warning(
                "[CPE MATCH API] Error fetching CPEs, continuing without CPE data",
                meta={"cve_id": cve_id, "error": str(err)},
            )
            return []

        return list(cpe_names)

    @staticmethod
    def _extract_cpe_names(
        data: dict,
        cpe_names: set[str],
        modified_since: datetime | None = None,
    ) -> None:
        """Extract CPE names from a CPE Match API response.

        The response contains a list of matchStrings, each containing a match
        criteria pattern and a list of concrete CPE matches with cpeName fields.
        We only extract the concrete cpeName values from matches, not the
        criteria pattern itself (which may contain wildcards or version ranges).

        When `modified_since` is set, a match string is kept only if the more
        recent of its `lastModified` and `cpeLastModified` is not before it
        (`lastModified` changes when the match criteria is created or its
        status changes, `cpeLastModified` when a CPE name under it is
        created, modified or deprecated). NVD returns naive ISO strings (e.g.
        "2023-02-09T19:31:01.650"), which are treated as UTC. A field that is
        missing or unparseable is ignored; a match string with neither usable
        is kept.

        Args:
            data: The JSON response from the CPE Match API.
            cpe_names: A set to collect unique CPE name strings into.
            modified_since: Optional lower bound on the more recent of
                `matchString.lastModified` and `matchString.cpeLastModified`.
                A naive value is treated as UTC.
        """
        if modified_since is not None and modified_since.tzinfo is None:
            modified_since = modified_since.replace(tzinfo=timezone.utc)

        def parse_date(value: object) -> datetime | None:
            if not isinstance(value, str):
                return None
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed

        def is_modified_since_threshold(match_criteria: dict) -> bool:
            if modified_since is None:
                return True
            dates = [
                parsed
                for parsed in (
                    parse_date(match_criteria.get("lastModified")),
                    parse_date(match_criteria.get("cpeLastModified")),
                )
                if parsed is not None
            ]
            if not dates:
                # No usable date: keep the match string.
                return True
            return max(dates) >= modified_since

        def add_cpe_name(candidate: object) -> None:
            if isinstance(candidate, str) and candidate.strip():
                cpe_names.add(candidate)

        for match_string in data.get("matchStrings", []):
            match_criteria = match_string.get("matchString", {})
            if not is_modified_since_threshold(match_criteria):
                continue
            for match in match_criteria.get("matches", []):
                add_cpe_name(match.get("cpeName"))
