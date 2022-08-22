import datetime
import logging
import re
from typing import List

import titan_client
from pytz import UTC
from stix2 import TLP_AMBER, Bundle, ExternalReference, Report

from .common import BaseMapper, StixMapper, author_identity, generate_id

log = logging.getLogger(__name__)


class AbstractReportMapper(BaseMapper):
    report_type_ov = {
        "account checking": "",
        "actor profile": "threat-actor",
        "airlines": "",
        "ajax security team": "",
        "anonymous": "",
        "atms": "",
        "banking & finance": "",
        "blackhat seo": "",
        "bulletproof hosting": "tool",
        "cashout & moneymules": "",
        "click fraud": "",
        "credit card fraud": "",
        "crypters & packers": "",
        "cryptocurrency": "",
        "database dumps": "",
        "denial of service": "tool",
        "document fraud": "",
        "drops - accounts": "",
        "drops - mail": "",
        "e-commerce": "",
        "exploit kit": "tool",
        "exploit kit - usage": "tool",
        "extortion": "",
        "gaming": "",
        "government & defense industrial base": "",
        "hack the planet": "",
        "healthcare": "",
        "industrial espionage": "",
        "infrastructure": "",
        "injects": "",
        "insider": "",
        "iot (internet of things)": "",
        "law firms & legal": "",
        "lizard squad": "",
        "malware": "malware",
        "malware - technical": "malware",
        "malware - usage": "malware",
        "mobile": "",
        "new tag1": "",
        "new tag2": "",
        "phishing": "",
        "pii & fullz": "",
        "pos": "",
        "ransomware": "",
        "resources & mining": "",
        "retail": "",
        "shipping service": "",
        "skimmers": "tool",
        "social networking": "",
        "spam": "",
        "sport industry": "",
        "syrian electronic army": "",
        "targeted attack": "",
        "tickets, hotel and travel": "",
        "tools": "tool",
        "ttps": "",
        "vulnerabilities & exploits": "vulnerability",
    }

    def map(self, source: dict, girs_names: dict = None) -> Bundle:
        container = self.map_reports(source)
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle

    def map_reports(self, source: dict, object_refs: dict = None) -> dict:
        raise NotImplementedError

    def get_name(self, subject, *categories):
        categories = [i for i in categories if i]
        if categories:
            name = f"[{'/'.join(categories)}] {subject}"
        else:
            name = subject
        return self.shorten(name, 128)

    def map_report_types(self, tags: List[str]) -> List[str]:
        types = set()
        for tag in tags:
            ov_type = self.report_type_ov.get(tag.lower())
            if ov_type:
                types.add(ov_type)
        if not types:
            types.add("miscellaneous")
        return sorted(list(types))

    def format_published(self, value: datetime):
        """
        Formatting datetime object for use as ID contributing property in a same way as it's done by OpenCTI
        to have the same ID here and in OpenCTI.
        """
        return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@StixMapper.register("reports", lambda x: "reportTotalCount" in x)
@StixMapper.register("report", lambda x: "subject" in x and "portalReportUrl" in x)
class ReportMapper(AbstractReportMapper):

    remove_html = re.compile("<.*?>")

    def __init__(self, api_config: titan_client.Configuration):
        super().__init__(api_config)
        self.full_reports_cache = {}
        self.portal2api_map = {
            "inforep": ("ReportsApi", "reports_uid_get", "raw_text"),
            "fintel": ("ReportsApi", "reports_uid_get", "raw_text"),
            "breach_alert": (
                "ReportsApi",
                "breach_alerts_uid_get",
                "data.breach_alert.summary",
            ),
            "spotrep": (
                "ReportsApi",
                "spot_reports_uid_get",
                "data.spot_report.spot_report_data.text",
            ),
            "malrep": (
                "ReportsApi",
                "malware_reports_uid_get",
                "data.malware_report_data.text",
            ),
            "sitrep": (
                "ReportsApi",
                "situation_reports_report_uid_get",
                "data.situation_report.text",
            ),
            "cve": (
                "VulnerabilitiesApi",
                "cve_reports_uid_get",
                "data.cve_report.summary",
            ),
        }

    def _get_description(self, report_url: str):
        if report_url not in self.full_reports_cache:
            _, _, _, _, report_type, uid = report_url.split("/")
            api_cls, api_method, content_field = self.portal2api_map.get(report_type)
            with titan_client.ApiClient(self.api_config) as api_client:
                api_instance = getattr(titan_client, api_cls)(api_client)
                api_response = getattr(api_instance, api_method)(uid)
            item = api_response
            for i in content_field.split("."):
                item = getattr(item, i, "")
            self.full_reports_cache[report_url] = re.sub(self.remove_html, "", item)
        return self.full_reports_cache[report_url]

    def map_reports(self, source: dict, object_refs: dict = None) -> dict:
        container = {}
        items = (
            source.get("reports") or [] if "reportTotalCount" in source else [source]
        )
        for item in items:
            report_uid = item["uid"]
            report_family = item.get("documentFamily")
            report_type = item.get("documentType")
            report_url = item["portalReportUrl"]
            report_subject = item["subject"]
            try:
                report_description = self._get_description(report_url)
            except Exception as e:
                log.warning("Cannot build the report's description. Error: %s", e)
                report_description = report_subject
            report_types = self.map_report_types(item.get("tags") or [])
            created = datetime.datetime.fromtimestamp(
                item.get("released", item.get("created")) / 1000, UTC
            )

            collected_object_refs = {}
            if object_refs:
                collected_object_refs.update(object_refs)
            for entity_source in item.get("entities") or []:
                entity = self.map_entity(entity_source["type"], entity_source["value"])
                if entity:
                    collected_object_refs[entity.id] = entity
            for location_source in item.get("locations") or []:
                location = self.map_location(
                    location_source.get("region"), location_source.get("country")
                )
                if location:
                    collected_object_refs[location.id] = location
            if collected_object_refs:
                name = self.get_name(report_subject, report_family, report_type)
                report = Report(
                    id=generate_id(
                        Report,
                        name=name.strip().lower(),
                        published=self.format_published(created),
                    ),
                    name=name,
                    description=report_description,
                    report_types=report_types,
                    published=self.format_published(created),
                    object_refs=collected_object_refs.values(),
                    external_references=[
                        ExternalReference(source_name="Titan URL", url=report_url)
                    ],
                    created_by_ref=author_identity,
                    object_marking_refs=[TLP_AMBER],
                    custom_properties={"x_intel471_com_uid": report_uid},
                )
                container[report.id] = report
                container[author_identity.id] = author_identity
                container[TLP_AMBER.id] = TLP_AMBER
                container.update(collected_object_refs)
            else:
                log.warning(f"Can't map any entities from report {report_uid}")
        return container
