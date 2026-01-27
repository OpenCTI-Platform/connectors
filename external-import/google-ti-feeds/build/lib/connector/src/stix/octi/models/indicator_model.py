"""The module contains the OctiIndicatorModel class, which represents an OpenCTI Indicator."""

from datetime import datetime
from typing import Any

from connector.src.stix.octi.observable_type_ov_enum import ObservableTypeOV
from connector.src.stix.octi.pattern_type_ov_enum import PatternTypeOV
from connector.src.stix.octi.platform_ov_enum import PlatformOV
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel


class OctiIndicatorModel:
    """Model for creating OpenCTI Indicator objects."""

    @staticmethod
    def create(
        name: str,
        pattern: str,
        pattern_type: PatternTypeOV,
        observable_type: ObservableTypeOV,
        organization_id: str,
        marking_ids: list[str],
        description: str | None = None,
        indicator_types: list[IndicatorTypeOV] | None = None,
        platforms: list[PlatformOV] | None = None,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        kill_chain_phases: list[KillChainPhaseModel] | None = None,
        score: int | None = None,
        external_references: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> IndicatorModel:
        """Create an Indicator model.

        Args:
            name: The name of the indicator
            pattern: The detection pattern (e.g., STIX pattern, YARA rule, etc.)
            pattern_type: The type of pattern from PatternTypeOV enum
            observable_type: The type of observable this indicator detects from ObservableTypeOV enum
            organization_id: The ID of the organization that created this indicator
            marking_ids: list of marking definition IDs to apply to the indicator
            description: Description of the indicator
            indicator_types: Types of the indicator from IndicatorTypeOV enum
            platforms: Platforms where this indicator is applicable from PlatformOV enum
            valid_from: Timestamp when the indicator becomes valid
            valid_until: Timestamp when the indicator is no longer valid
            kill_chain_phases: Kill chain phases associated with the indicator
            score: Confidence score of the indicator (0-100)
            external_references: External references related to the indicator
            **kwargs: Additional arguments to pass to IndicatorModel

        Returns:
            IndicatorModel: The created indicator model

        """
        custom_properties = kwargs.pop("custom_properties", {})
        if score:
            custom_properties["x_opencti_score"] = score
        if platforms:
            custom_properties["x_mitre_platforms"] = platforms
        if observable_type:
            custom_properties["x_opencti_main_observable_type"] = observable_type

        data = {
            "type": "indicator",
            "spec_version": "2.1",
            "custom_properties": custom_properties,
            "created": kwargs.pop("created", datetime.now()),
            "modified": kwargs.pop("modified", datetime.now()),
            "name": name,
            "description": description,
            "indicator_types": indicator_types or [IndicatorTypeOV.MALICIOUS_ACTIVITY],
            "pattern": pattern,
            "pattern_type": pattern_type,
            "valid_from": valid_from or datetime.now(),
            "valid_until": valid_until,
            "kill_chain_phases": kill_chain_phases,
            "external_references": external_references,
            "created_by_ref": organization_id,
            "object_marking_refs": marking_ids,
            **kwargs,
        }

        return IndicatorModel(**data)
