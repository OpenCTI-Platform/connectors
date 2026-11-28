from src.services.client.api import CVEClient
from src.services.utils.constants import MAX_CPE_PAGES_PER_CVE, MAX_CPES_PER_CVE

CPE_MATCH_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"


class CPEMatchClient(CVEClient):
    """Async client for the NVD CPE Match API.

    Resolves CPE names associated with a given CVE ID.
    API documentation: https://nvd.nist.gov/developers/products
    """

    async def get_cpes_for_cve(
        self, cve_id: str, request_params: dict | None = None
    ) -> list[str]:
        """Retrieve a bounded selection of unique CPE names associated with a CVE.

        Calls the NVD CPE Match API with the given CVE ID, handles pagination,
        and returns a deduplicated list of CPE Name strings.

        Args:
            cve_id: The CVE identifier (e.g. "CVE-2022-32223").

        Returns:
            A deduplicated list of CPE Name strings (format cpe:2.3:...).
        """
        cpe_names: set[str] = set()
        params: dict = {
            **(request_params or {}),
            "cveId": cve_id,
            "resultsPerPage": 100,
        }

        debug_msg = f"[CPE MATCH API] Fetching CPE matches for {cve_id}"
        self.helper.connector_logger.debug(debug_msg)

        try:
            data = await self.get_complete_collection(CPE_MATCH_BASE_URL, params)
            if data is None:
                warn_msg = (
                    f"[CPE MATCH API] No response for {cve_id}, "
                    f"skipping CPE resolution."
                )
                self.helper.connector_logger.warning(warn_msg)
                return []

            self._extract_cpe_names(data, cpe_names)

            # Handle pagination
            total_results = data.get("totalResults", 0)
            results_per_page = data.get("resultsPerPage", 0)

            if not isinstance(results_per_page, int) or results_per_page <= 0:
                if total_results:
                    self.helper.connector_logger.warning(
                        f"[CPE MATCH API] Unexpected resultsPerPage={results_per_page} "
                        f"for {cve_id}; stopping pagination to avoid infinite loop."
                    )
                return list(cpe_names)

            start_index = results_per_page

            pages_fetched = 1
            while (
                start_index < total_results
                and len(cpe_names) < MAX_CPES_PER_CVE
                and pages_fetched < MAX_CPE_PAGES_PER_CVE
            ):
                paginated_params = {
                    **params,
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                }
                page_data = await self.get_complete_collection(
                    CPE_MATCH_BASE_URL, paginated_params
                )
                if page_data is None:
                    break
                pages_fetched += 1
                self._extract_cpe_names(page_data, cpe_names)
                results_per_page = page_data.get("resultsPerPage", 0)
                if not isinstance(results_per_page, int) or results_per_page <= 0:
                    self.helper.connector_logger.warning(
                        f"[CPE MATCH API] Unexpected page resultsPerPage={results_per_page} "
                        f"for {cve_id}; stopping pagination to avoid infinite loop."
                    )
                    break
                start_index += results_per_page

            if len(cpe_names) >= MAX_CPES_PER_CVE or (
                start_index < total_results and pages_fetched >= MAX_CPE_PAGES_PER_CVE
            ):
                self.helper.connector_logger.warning(
                    f"[CPE MATCH API] Resource limit reached for {cve_id}; CPE results truncated."
                )

            debug_msg = (
                f"[CPE MATCH API] Found {len(cpe_names)} unique CPEs for {cve_id}"
            )
            self.helper.connector_logger.debug(debug_msg)

        except Exception as err:
            warn_msg = (
                f"[CPE MATCH API] Error fetching CPEs for {cve_id}: {err!s}. "
                f"Continuing without CPE data."
            )
            self.helper.connector_logger.warning(warn_msg)
            return []

        return sorted(cpe_names)

    @staticmethod
    def _extract_cpe_names(data: dict, cpe_names: set[str]) -> None:
        """Extract CPE names from a CPE Match API response.

        The response contains a list of matchStrings, each containing a match
        criteria pattern and a list of concrete CPE matches with cpeName fields.
        We only extract the concrete cpeName values from matches, not the
        criteria pattern itself (which may contain wildcards or version ranges).

        Args:
            data: The JSON response from the CPE Match API.
            cpe_names: A set to collect unique CPE name strings into.
        """

        def add_cpe_name(candidate: object) -> None:
            if isinstance(candidate, str) and candidate.strip():
                cpe_names.add(candidate)

        for match_string in data.get("matchStrings", []):
            match_criteria = match_string.get("matchString", {})
            for match in match_criteria.get("matches", []):
                if len(cpe_names) >= MAX_CPES_PER_CVE:
                    return
                add_cpe_name(match.get("cpeName"))
