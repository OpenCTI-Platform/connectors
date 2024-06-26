# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike report fetcher module."""

import logging
from typing import Any, Dict, List, Mapping, Optional, Union

from crowdstrike_feeds_services.client.reports import ReportsAPI
from pydantic import BaseModel

from . import create_file_from_download

logger = logging.getLogger(__name__)


class FetchedReport(BaseModel):
    """Fetched report model."""

    report: dict
    files: Any


class ReportFetcher:
    """CrowdStrike report fetcher."""

    _NOT_FOUND = object()

    def __init__(self, helper) -> None:
        """Initialize CrowdStrike report fetcher."""
        self.reports_api_cs = ReportsAPI(helper)

        self.fetched_report_cache: Dict[str, Union[FetchedReport, object]] = {}

    @staticmethod
    def _info(msg: str, *args: Any) -> None:
        logger.info(msg, *args)

    @staticmethod
    def _error(msg: str, *args: Any) -> None:
        logger.error(msg, *args)

    def clear_cache(self) -> None:
        """Clear report fetcher cache."""
        self.fetched_report_cache.clear()

    def _get_cache(self, report_code: str) -> Optional[Union[FetchedReport, object]]:
        return self.fetched_report_cache.get(report_code)

    def _put_cache(
        self, report_code: str, fetched_report: Union[FetchedReport, object]
    ) -> None:
        self.fetched_report_cache[report_code] = fetched_report

    def get_by_codes(self, codes: List[str]) -> List[FetchedReport]:
        """Get reports by their codes."""
        fetched_reports = []
        for code in codes:
            fetched_report = self.get_by_code(code)
            if fetched_report is None:
                continue
            fetched_reports.append(fetched_report)
        return fetched_reports

    def get_by_code(self, code: str) -> Optional[FetchedReport]:
        """Get report by the code."""
        self._info("Get report by code: '%s'...", code)

        fetched_report = self._get_cache(code)

        if fetched_report is self._NOT_FOUND:
            self._info("Returning cached 'not found' for code: '%s'", code)
            return None

        if fetched_report is not None and isinstance(fetched_report, FetchedReport):
            self._info("Returning cached report for code: '%s'", code)
            return fetched_report

        report = self._fetch_report(code)
        if report is None:
            self._put_cache(code, self._NOT_FOUND)
            return None

        files = []
        file = self._get_report_pdf(report["id"], report["name"])
        if file is not None:
            files.append(file)

        fetched_report = FetchedReport(report=report, files=files)

        self._put_cache(code, fetched_report)

        return fetched_report

    def _fetch_report(self, code: str) -> Optional:
        self._info("Fetching report by code '%s'...", code)

        ids = [code]
        fields = ["__full__"]

        response = self.reports_api_cs.get_report_entities(ids, fields)

        resources = response["resources"]
        if resources is not None:
            resources_count = len(resources)
        else:
            resources_count = 0

        if resources_count == 0:
            self._info("Report code '%s' returned nothing", code)
            return None

        if resources_count > 1:
            self._error("Report code '%s' returned more than one result", code)
            return None

        report = resources[0]

        self._info("Fetched report (id: '%s') by code '%s'", report["id"], code)

        return report

    def _get_report_pdf(
        self, report_id: int, report_name: str
    ) -> Optional[Mapping[str, str]]:
        self._info("Fetching report PDF by id '%s'...", report_id)

        download = self.reports_api_cs.get_report_pdf(str(report_id))

        if type(download) is dict:
            self._info("No report PDF for id '%s'", report_id)
            return None
        else:
            return create_file_from_download(download, report_name)
