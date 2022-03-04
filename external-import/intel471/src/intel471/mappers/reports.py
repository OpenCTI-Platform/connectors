import datetime
import logging

from stix2 import Bundle, Report, Malware, ExternalReference, TLP_AMBER

from .common import StixMapper, BaseMapper, generate_id, author_identity

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

    def map(self, source: dict) -> Bundle:
        if container := self.map_reports(source):
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

    def map_report_types(self, tags: list[str]) -> list[str]:
        types = set()
        for tag in tags:
            if ov_type := self.report_type_ov.get(tag.lower()):
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
    def map_reports(self, source: dict, object_refs: dict = None) -> dict:
        container = {}
        items = source.get("reports") or [] if "reportTotalCount" in source else [source]
        for item in items:
            report_uid = item["uid"]
            report_family = item.get("documentFamily")
            report_type = item.get("documentType")
            report_subject = item["subject"]
            report_url = item["portalReportUrl"]
            report_types = self.map_report_types(item.get("tags") or [])
            created = datetime.datetime.fromtimestamp(item.get("released", item.get("created")) / 1000)

            collected_object_refs = {}
            if object_refs:
                collected_object_refs.update(object_refs)
            for entity_source in item.get("entities") or []:
                if entity := self.map_entity(entity_source["type"], entity_source["value"]):
                    collected_object_refs[entity.id] = entity
            for location_source in item.get("locations") or []:
                if location := self.map_location(location_source.get("region"), location_source.get("country")):
                    collected_object_refs[location.id] = location
            if collected_object_refs:
                name = self.get_name(report_subject, report_family, report_type)
                report = Report(id=generate_id(Report, name=name.strip().lower(), published=self.format_published(created)),
                                name=name,
                                report_types=report_types,
                                published=self.format_published(created),
                                object_refs=collected_object_refs.values(),
                                external_references=[ExternalReference(source_name="Titan URL", url=report_url)],
                                created_by_ref=author_identity,
                                object_marking_refs=[TLP_AMBER],
                                custom_properties={"x_intel471_com_uid": report_uid})
                container[report.id] = report
                container[author_identity.id] = author_identity
                container.update(collected_object_refs)
            else:
                log.warning(f"Can't map any entities from report {report_uid}")
        return container
