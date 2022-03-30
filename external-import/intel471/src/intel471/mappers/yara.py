import datetime

import yaml
from pytz import UTC
from stix2 import Indicator, Bundle, Relationship, Malware, TLP_AMBER
from .common import StixMapper, BaseMapper, generate_id, author_identity


@StixMapper.register("yara", lambda x: "yaraTotalCount" in x)
class YaraMapper(BaseMapper):

    def map(self, source: dict, girs_names: dict = None) -> Bundle:
        container = {}
        items = source.get("yaras") or [] if "yaraTotalCount" in source else [source]
        for item in items:
            yara_uid = item["uid"]
            yara_signature = item["data"]["yara_data"]["signature"]
            malware_family_name = item["data"]["threat"]["data"]["family"]
            malware_family_uid = item["data"]["threat"]["data"]["malware_family_profile_uid"]
            valid_from = datetime.datetime.fromtimestamp(item["activity"]["first"] / 1000, UTC)
            confidence = self.map_confidence(item["data"]["confidence"])
            girs_paths = item["data"]["intel_requirements"]
            girs_names = girs_names or {}
            girs = [{"path": i, "name": girs_names.get(i)} for i in girs_paths]
            description = f"### Intel requirements\n\n```yaml\n{yaml.dump(girs)}```"

            malware = Malware(id=generate_id(Malware, name=malware_family_name.strip().lower()),
                              name=malware_family_name,
                              is_family=True,
                              created_by_ref=author_identity,
                              object_marking_refs=[TLP_AMBER],
                              custom_properties={"x_intel471_com_uid": malware_family_uid})

            indicator = Indicator(id=generate_id(Indicator, pattern=yara_signature),
                                  description=description,
                                  indicator_types=["malicious-activity"],
                                  pattern_type="yara",
                                  pattern=yara_signature,
                                  valid_from=valid_from,
                                  created_by_ref=author_identity,
                                  confidence=confidence,
                                  object_marking_refs=[TLP_AMBER],
                                  custom_properties={"x_intel471_com_uid": yara_uid})
            relationship = Relationship(indicator, "indicates", malware, created_by_ref=author_identity)
            container[malware.id] = malware
            container[indicator.id] = indicator
            container[author_identity.id] = author_identity
            container[relationship.id] = relationship
            container[TLP_AMBER.id] = TLP_AMBER
        if container:
            bundle = Bundle(*container.values(), allow_custom=True)
            return bundle
