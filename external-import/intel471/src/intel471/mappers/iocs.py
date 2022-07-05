import datetime
import logging
from typing import Union

from pytz import UTC
from stix2 import Bundle, Indicator, Report, TLP_AMBER, DomainName, URL, Relationship

from .patterning import create_domain_pattern, create_url_pattern
from .observables import create_domain, create_url
from .reports import ReportMapper
from .common import StixMapper, BaseMapper, generate_id, author_identity, MappingConfig

log = logging.getLogger(__name__)


@StixMapper.register("iocs", lambda x: "iocTotalCount" in x)
class IOCMapper(BaseMapper):

    mapping_configs = {
        "MaliciousURL": MappingConfig(
            patterning_mapper=create_url_pattern,
            observable_mapper=create_url,
            kwargs_extractor=lambda i: {"value": i["value"]},
        ),
        "MaliciousDomain": MappingConfig(
            patterning_mapper=create_domain_pattern,
            observable_mapper=create_domain,
            kwargs_extractor=lambda i: {"value": i["value"].split("://")[-1]},
        ),
    }

    def map(self, source: dict, girs_names: dict = None) -> Bundle:
        container = {}
        report_mapper = ReportMapper(self.api_config)
        items = source.get("iocs") or [] if "iocTotalCount" in source else [source]
        for item in items:
            ioc_type = item["type"]
            mapping_config = self.mapping_configs.get(ioc_type)
            if not mapping_config:
                continue
            report_sources = item["links"].get("reports") or []
            valid_from = datetime.datetime.fromtimestamp(item["activeFrom"] / 1000, UTC)
            valid_until = datetime.datetime.fromtimestamp(
                item["activeTill"] / 1000, UTC
            )
            if valid_from == valid_until:
                valid_until = None

            kwargs = mapping_config.kwargs_extractor(item)
            stix_pattern = mapping_config.patterning_mapper(**kwargs)
            observable = mapping_config.observable_mapper(**kwargs)
            indicator = Indicator(
                id=generate_id(Indicator, pattern=stix_pattern),
                pattern_type="stix",
                pattern=stix_pattern,
                indicator_types=["malicious-activity"],
                valid_from=valid_from,
                valid_until=valid_until,
                created_by_ref=author_identity,
                object_marking_refs=[TLP_AMBER],
            )
            r1 = Relationship(
                indicator, "based-on", observable, created_by_ref=author_identity
            )
            for stix_object in [indicator, observable, r1, author_identity, TLP_AMBER]:
                container[stix_object.id] = stix_object
            for uid, stix_object in self.map_reports(
                report_mapper, report_sources, indicator, observable
            ).items():
                if isinstance(stix_object, Report) and uid in container:
                    stix_object.object_refs.extend(container[uid].object_refs)
                container[uid] = stix_object
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle

    def map_reports(
        self,
        report_mapper,
        report_sources: list,
        indicator: Indicator,
        observable: Union[URL, DomainName],
    ) -> dict:
        container = {}
        for report_source in report_sources:
            container.update(
                report_mapper.map_reports(
                    report_source,
                    object_refs={indicator.id: indicator, observable.id: observable},
                )
            )
        return container
