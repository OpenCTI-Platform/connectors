from __future__ import annotations

from typing import Any

import pycti
import stix2
from models._common import _BaseCommon


class Location(_BaseCommon):
    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        location_type="Country",
        region_value=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.location_type = location_type
        self.region_value = region_value

    def _generate_common(self) -> Any:
        if self.location_type == "Region":
            display = str(self.name)
            region_slug = str(self.region_value or display).lower().replace(" ", "-")
            custom = {
                **self._labels_kv(),
                "x_opencti_location_type": "Region",
                "x_opencti_external_references": self.external_references,
                "x_opencti_created_by_ref": self.author.id,
            }
            self.stix_main_object = stix2.Location(
                id=pycti.Location.generate_id(display, "Region"),
                name=display,
                description=self.description,
                region=region_slug,
                object_marking_refs=self.get_markings(),
                custom_properties=custom,
            )
            return self.stix_main_object
        country_name = self._generate_country_by_cc(self.name) or str(self.name)
        custom = {
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
            "x_opencti_aliases": self.name,
            "x_opencti_created_by_ref": self.author.id,
        }
        self.stix_main_object = stix2.Location(
            id=pycti.Location.generate_id(country_name, self.location_type),
            name=country_name,
            description=self.description,
            country=self.name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
        )
        return self.stix_main_object


class KillChainPhase(_BaseCommon):
    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _generate_common(self) -> Any:
        custom = {
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
            "x_opencti_created_by_ref": self.author.id,
        }
        self.stix_main_object = stix2.KillChainPhase(
            kill_chain_name=self.name,
            phase_name=self.c_type,
            custom_properties=custom,
        )
        return self.stix_main_object
