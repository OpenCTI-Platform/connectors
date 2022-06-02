# -*- coding: utf-8 -*-
"""OpenCTI RiskIQ's article importer module."""
import datetime
import itertools
from typing import Any, Mapping, Optional

import stix2
from dateutil import parser
from pycti import OpenCTIConnectorHelper, Report
from stix2 import utils
from stix2.v21 import _Observable

from .utils import datetime_to_timestamp


class ArticleImporter:
    """Article importer class."""

    _LATEST_ARTICLE_TIMESTAMP = "latest_article_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        article: dict[str, Any],
        author: stix2.Identity,
        create_indicators: bool,
    ):
        """Initialization of the article importer."""
        self.helper = helper
        self.article = article
        self.author = author
        self.work_id: Optional[str] = None
        # Use custom properties to set the author and the confidence level of the object.
        self.custom_props = {
            "x_opencti_created_by_ref": self.author["id"],
            "x_opencti_create_indicator": create_indicators,
        }

    def _process_indicator(self, indicator: stix2.Indicator) -> list[_Observable]:
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
        tlp_marking = (
            stix2.TLP_WHITE if indicator["source"] == "public" else stix2.TLP_AMBER
        )

        try:
            if indicator_type == "hash_md5":
                return [
                    stix2.File(
                        type="file",
                        hashes={"MD5": v},
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in ["hash_sha1", "sha1"]:
                return [
                    stix2.File(
                        type="file",
                        hashes={"SHA-1": v},
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in ["sha256", "hash_sha256"]:
                return [
                    stix2.File(
                        type="file",
                        hashes={"SHA-256": v},
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type == "domain":
                return [
                    stix2.DomainName(
                        type="domain-name",
                        value=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in ["email", "emails"]:
                return [
                    stix2.EmailAddress(
                        type="email-addr",
                        value=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in ["filename", "filepath"]:
                return [
                    stix2.File(
                        type="file",
                        name=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type == "ip":
                return [
                    stix2.IPv4Address(
                        type="ipv4-addr",
                        value=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in ["proces_mutex", "process_mutex", "mutex"]:
                return [
                    stix2.Mutex(
                        type="mutex",
                        name=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type == "url":
                return [
                    stix2.URL(
                        type="url",
                        value=v,
                        object_marking_refs=tlp_marking,
                        defanged=False,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type == "certificate_sha1":
                return [
                    stix2.X509Certificate(
                        type="x509-certificate",
                        hashes={"SHA-1": v},
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in [
                "certificate_issuerorganizationname",
                "certificate_issuercommonname",
            ]:
                return [
                    stix2.X509Certificate(
                        type="x509-certificate",
                        issuer=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in [
                "certificate_subjectorganizationname",
                "certificate_subjectcountry",
                "certificate_subjectcommonname",
            ]:
                return [
                    stix2.X509Certificate(
                        type="x509-certificate",
                        subject=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]

            if indicator_type in [
                "certificate_serialnumber",
                "code_certificate_serial",
            ]:
                return [
                    stix2.X509Certificate(
                        type="x509-certificate",
                        serial_number=v,
                        object_marking_refs=tlp_marking,
                        custom_properties=self.custom_props,
                    )
                    for v in values
                ]
        except Exception as e:
            self.helper.log_error(f"[RiskIQ] Fail to create the SCO (error: {str(e)})")
            return []

        self.helper.log_warning(
            f"[RiskIQ] indicator with key {indicator_type} not supported. (Values: {values})"
        )
        return []

    def run(self, work_id: str, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run the importation of the article."""
        self.work_id = work_id
        created = parser.parse(self.article["createdDate"])
        # RisIQ API does not always provide the `publishedDate`.
        # If it does not exist, take the value of the `createdDate` instead.
        published = (
            parser.parse(self.article["publishedDate"])
            if self.article["publishedDate"] is not None
            else created
        )

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

        # Check if all indicators' TLP marking are `TLP_WHITE`.
        report_tlp = stix2.TLP_WHITE
        if stix2.TLP_AMBER in [i["object_marking_refs"][0] for i in indicators]:
            report_tlp = stix2.TLP_AMBER

        report = stix2.Report(
            id=Report.generate_id(
                self.article.get("title", "RiskIQ Threat Report"), published
            ),
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
            object_marking_refs=report_tlp,
            external_references=[
                {
                    "source_name": "riskiq",
                    "url": self.article["link"],
                    "external_id": self.article["guid"],
                }
            ],
            allow_custom=True,
        )
        self.helper.log_debug(f"[RiskIQ] Report = {report}")

        bundle = stix2.Bundle(
            objects=indicators + [report, self.author], allow_custom=True
        )
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

    def _send_bundle(self, bundle: stix2.Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=self.work_id)
