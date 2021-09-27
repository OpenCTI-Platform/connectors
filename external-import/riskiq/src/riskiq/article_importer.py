# -*- coding: utf-8 -*-
"""OpenCTI RiskIQ's article importer module."""
import datetime
import itertools
from typing import Any, Mapping, Optional

from dateutil import parser
from pycti import OpenCTIConnectorHelper
from stix2 import (
    Bundle,
    DomainName,
    EmailAddress,
    File,
    Identity,
    Indicator,
    IPv4Address,
    Mutex,
    Report,
    TLP_AMBER,
    TLP_WHITE,
    URL,
    X509Certificate,
    utils,
)
from stix2.v21 import _Observable

from .utils import datetime_to_timestamp


class ArticleImporter:
    """Article importer class."""

    _LATEST_ARTICLE_TIMESTAMP = "latest_article_timestamp"

    def __init__(
        self, helper: OpenCTIConnectorHelper, article: dict[str, Any], author: Identity
    ):
        """Initialization of the article importer."""
        self.helper = helper
        self.article = article
        self.author = author
        self.work_id: Optional[str] = None

    def _process_indicator(self, indicator: Indicator) -> list[_Observable]:
        """
        Process the indicator depending on its type.

        Parameters
        ----------
        indicator : Indicator
            One indicator from an article.

        Returns
        -------
        List of Observable
            A list of Observable depending on the indicator type.
        """
        indicator_type = indicator["type"]
        values = indicator["values"]
        tlp_marking = TLP_AMBER if indicator["source"] != "public" else TLP_WHITE

        if indicator_type == "hash_md5":
            return [
                File(
                    type="file",
                    hashes={"MD5": v},
                    object_marking_refs=tlp_marking,
                )
                for v in values
            ]

        if indicator_type in ["hash_sha1", "sha1"]:
            return [
                File(
                    type="file",
                    hashes={"SHA-1": v},
                    object_marking_refs=tlp_marking,
                )
                for v in values
            ]

        if indicator_type in ["sha256", "hash_sha256"]:
            return [
                File(
                    type="file",
                    hashes={"SHA-256": v},
                    object_marking_refs=tlp_marking,
                )
                for v in values
            ]

        if indicator_type == "domain":
            return [
                DomainName(type="domain-name", value=v, object_marking_refs=tlp_marking)
                for v in values
            ]

        if indicator_type in ["email", "emails"]:
            return [
                EmailAddress(
                    type="email-addr", value=v, object_marking_refs=tlp_marking
                )
                for v in values
            ]

        if indicator_type in ["filename", "filepath"]:
            return [
                File(type="file", name=v, object_marking_refs=tlp_marking)
                for v in values
            ]

        if indicator_type == "ip":
            return [
                IPv4Address(type="ipv4-addr", value=v, object_marking_refs=tlp_marking)
                for v in values
            ]

        if indicator_type in ["proces_mutex", "process_mutex", "mutex"]:
            return [
                Mutex(type="mutex", name=v, object_marking_refs=tlp_marking)
                for v in values
            ]

        if indicator_type == "url":
            return [
                URL(
                    type="url", value=v, object_marking_refs=tlp_marking, defanged=False
                )
                for v in values
            ]

        if indicator_type == "certificate_sha1":
            return [
                X509Certificate(
                    type="x509-certificate",
                    hashes={"SHA-1": v},
                    object_marking_refs=tlp_marking,
                )
                for v in values
            ]

        if indicator_type in [
            "certificate_issuerorganizationname",
            "certificate_issuercommonname",
        ]:
            return [
                X509Certificate(
                    type="x509-certificate", issuer=v, object_marking_refs=tlp_marking
                )
                for v in values
            ]

        if indicator_type in [
            "certificate_subjectorganizationname",
            "certificate_subjectcountry",
            "certificate_subjectcommonname",
        ]:
            return [
                X509Certificate(
                    type="x509-certificate", subject=v, object_marking_refs=tlp_marking
                )
                for v in values
            ]

        if indicator_type in ["certificate_serialnumber", "code_certificate_serial"]:
            return [
                X509Certificate(
                    type="x509-certificate",
                    serial_number=v,
                    object_marking_refs=tlp_marking,
                )
                for v in values
            ]

        self.helper.log_warning(
            f"[RiskIQ] indicator with key {indicator_type} not supported. (Values: {values})"
        )
        return []

    def run(self, work_id: str, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run the importation of the article."""
        self.work_id = work_id
        published = parser.parse(self.article["publishedDate"])
        created = parser.parse(self.article["createdDate"])

        indicators = itertools.chain(
            *[
                self._process_indicator(indicator)
                for indicator in self.article["indicators"]
            ]
        )

        indicators = utils.deduplicate(list(indicators))
        # Return the initial state if we don't have any indicators.
        if not indicators:
            self.helper.log_info("No indicator in article, report will not be created.")
            return state

        self.helper.log_debug(f"Number of indicators: {len(indicators)}")

        report = Report(
            type="report",
            name=self.article.get("title", "RiskIQ Threat Report"),
            description=self.article["summary"],
            report_types=["threat-report"],
            created_by_ref=self.author,
            created=created,
            published=published,
            lang="en",
            labels=self.article["tags"],
            object_refs=indicators,
            object_marking_refs=TLP_AMBER,
            external_references=[
                {
                    "source_name": "riskiq",
                    "url": self.article["link"],
                    "external_id": self.article["guid"],
                }
            ],
        )
        self.helper.log_debug(f"[RiskIQ] Report = {report}")

        bundle = Bundle(objects=indicators + [report, self.author])
        self.helper.log_info("[RiskIQ] Sending report STIX2 bundle")
        self._send_bundle(bundle)

        return self._create_state(created)

    @classmethod
    def _create_state(
        cls, latest_datetime: Optional[datetime.datetime]
    ) -> Mapping[str, Any]:
        if latest_datetime is None:
            return {}

        return {cls._LATEST_ARTICLE_TIMESTAMP: datetime_to_timestamp(latest_datetime)}

    def _send_bundle(self, bundle: Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=self.work_id)
        self.helper.metric_inc("record_send", len(bundle.objects))
