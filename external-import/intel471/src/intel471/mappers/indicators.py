import datetime

import yaml
from pytz import UTC
from stix2 import Indicator, Bundle, Relationship, Malware, KillChainPhase, TLP_AMBER

from .common import StixMapper, BaseMapper, generate_id, author_identity, MappingConfig
from .patterning import create_url_pattern, create_ipv4_pattern, create_file_pattern
from .observables import create_url, create_ipv4, create_file
from .sdo import create_malware


@StixMapper.register("indicators", lambda x: "indicatorTotalCount" in x)
class IndicatorsMapper(BaseMapper):

    mapping_configs = {
        "url": MappingConfig(
            patterning_mapper=create_url_pattern,
            observable_mapper=create_url,
            kwargs_extractor=lambda i: {"value": i["data"]["indicator_data"]["url"]}),
        "ipv4": MappingConfig(
            patterning_mapper=create_ipv4_pattern,
            observable_mapper=create_ipv4,
            kwargs_extractor=lambda i: {"value": i["data"]["indicator_data"]["address"]}),
        "file": MappingConfig(
            patterning_mapper=create_file_pattern,
            observable_mapper=create_file,
            kwargs_extractor=lambda i: {
                "md5": i["data"]["indicator_data"]["file"]["md5"],
                "sha1": i["data"]["indicator_data"]["file"]["sha1"],
                "sha256": i["data"]["indicator_data"]["file"]["sha256"]}
        )
    }

    def map(self, source: dict, girs_names: dict = None) -> Bundle:
        container = {}
        items = source.get("indicators") or [] if "indicatorTotalCount" in source else [source]
        for item in items:
            indicator_type = item["data"]["indicator_type"]
            mapping_config = self.mapping_configs.get(indicator_type)
            if not mapping_config:
                continue
            malware_family_name = item["data"]["threat"]["data"]["family"]
            valid_from = datetime.datetime.fromtimestamp(item["activity"]["first"] / 1000, UTC)
            valid_until = datetime.datetime.fromtimestamp(item["data"]["expiration"] / 1000, UTC)
            tactics = self.map_tactic(item["data"]["mitre_tactics"])
            confidence = self.map_confidence(item["data"]["confidence"])
            girs_paths = item["data"]["intel_requirements"]
            girs_names = girs_names or {}
            girs = [{"path": i, "name": girs_names.get(i)} for i in girs_paths]
            description_main = item["data"]["context"]["description"]
            description = f"{description_main}\n\n### Intel requirements\n\n```yaml\n{yaml.dump(girs)}```"


            kwargs = mapping_config.kwargs_extractor(item)
            stix_pattern = mapping_config.patterning_mapper(**kwargs)
            observable = mapping_config.observable_mapper(**kwargs)
            malware = create_malware(malware_family_name)
            indicator = Indicator(id=generate_id(Indicator, pattern=stix_pattern),
                                  pattern_type="stix",
                                  pattern=stix_pattern,
                                  indicator_types=["malicious-activity"],
                                  valid_from=valid_from,
                                  valid_until=valid_until,
                                  created_by_ref=author_identity,
                                  object_marking_refs=[TLP_AMBER],
                                  description=description,
                                  labels=[malware_family_name],
                                  confidence=confidence,
                                  kill_chain_phases=[KillChainPhase(kill_chain_name="mitre-attack", phase_name=tactics)])
            r1 = Relationship(indicator, "indicates", malware, created_by_ref=author_identity)
            r2 = Relationship(indicator, "based-on", observable, created_by_ref=author_identity)
            for stix_object in [malware, indicator, observable, r1, r2, author_identity, TLP_AMBER]:
                container[stix_object.id] = stix_object
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle
