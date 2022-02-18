import datetime
import logging

from stix2 import Bundle, Indicator, Report

from .patterning import STIXPatterningMapper
from .reports import ReportMapper
from .common import StixMapper, BaseMapper, generate_id, author_identity

log = logging.getLogger(__name__)


@StixMapper.register("iocs", lambda x: "iocTotalCount" in x)
class IOCMapper(BaseMapper):

    def map(self, source: dict) -> Bundle:
        container = {}
        items = source.get("iocs") or [] if "iocTotalCount" in source else [source]
        for item in items:
            ioc_type = item["type"]
            ioc_value = item["value"]
            ioc_id = item["uid"]
            report_sources = item["links"].get("reports") or []
            valid_from = datetime.datetime.fromtimestamp(item["activeFrom"] / 1000)
            valid_until = datetime.datetime.fromtimestamp(item["activeTill"] / 1000)
            if valid_from == valid_until:
                valid_until = None

            if pattern_mapper := getattr(STIXPatterningMapper, f"map_{ioc_type}", None):
                stix_pattern = pattern_mapper(ioc_value)
                indicator = Indicator(id=generate_id(Indicator, pattern=stix_pattern),
                                      indicator_types=["malicious-activity"],
                                      pattern_type="stix",
                                      pattern=stix_pattern,
                                      valid_from=valid_from,
                                      valid_until=valid_until,
                                      created_by_ref=author_identity,
                                      custom_properties={"x_intel471_com_uid": ioc_id})

                container[indicator.id] = indicator
                for uid, stix_object in self.map_reports(report_sources, indicator).items():
                    if isinstance(stix_object, Report) and uid in container:
                        stix_object.object_refs.extend(container[uid].object_refs)
                    container[uid] = stix_object
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle

    def map_reports(self, report_sources: list, indicator: Indicator) -> dict:
        container = {}
        report_mapper = ReportMapper()
        for report_source in report_sources:
            container.update(report_mapper.map_reports(report_source, object_refs={indicator.id: indicator}))
        return container
