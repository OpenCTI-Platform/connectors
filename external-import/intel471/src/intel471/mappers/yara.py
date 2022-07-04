import datetime

import yaml
from pytz import UTC
from stix2 import Indicator, Bundle, Relationship, TLP_AMBER
from .common import StixMapper, BaseMapper, generate_id, author_identity
from .sdo import create_malware


@StixMapper.register("yara", lambda x: "yaraTotalCount" in x)
class YaraMapper(BaseMapper):

    def map(self, source: dict, girs_names: dict = None) -> Bundle:
        container = {}
        items = source.get("yaras") or [] if "yaraTotalCount" in source else [source]
        for item in items:
            yara_signature = item["data"]["yara_data"]["signature"]
            malware_family_name = item["data"]["threat"]["data"]["family"]
            valid_from = datetime.datetime.fromtimestamp(item["activity"]["first"] / 1000, UTC)
            confidence = self.map_confidence(item["data"]["confidence"])
            girs_paths = item["data"]["intel_requirements"]
            girs_names = girs_names or {}
            girs = [{"path": i, "name": girs_names.get(i)} for i in girs_paths]
            description = f"### Intel requirements\n\n```yaml\n{yaml.dump(girs)}```"

            malware = create_malware(malware_family_name)
            indicator = Indicator(id=generate_id(Indicator, pattern=yara_signature),
                                  pattern_type="yara",
                                  pattern=yara_signature,
                                  indicator_types=["malicious-activity"],
                                  valid_from=valid_from,
                                  created_by_ref=author_identity,
                                  object_marking_refs=[TLP_AMBER],

                                  description=description,
                                  labels=[malware_family_name],
                                  confidence=confidence)
            relationship = Relationship(indicator, "indicates", malware, created_by_ref=author_identity)
            for stix_object in [malware, indicator, relationship, author_identity, TLP_AMBER]:
                container[stix_object.id] = stix_object
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle
