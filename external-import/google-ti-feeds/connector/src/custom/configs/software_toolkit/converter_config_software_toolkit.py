"""GTI converter configurations for software toolkits.

This module defines configurations for converting GTI software toolkit entities
to STIX format using the generic converter system.
"""

from connector.src.custom.configs.converter_config_common import (
    related_to_relationship,
    set_context_for,
    uses_relationship,
)
from connector.src.custom.exceptions import (
    GTIActorConversionError,
    GTIMalwareConversionError,
    GTISoftwareToolkitConversionError,
    GTITechniqueConversionError,
)
from connector.src.custom.mappers.gti_attack_techniques.gti_attack_technique_ids_to_stix_attack_patterns import (
    GTIAttackTechniqueIDsToSTIXAttackPatterns,
)
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_composite import (
    GTIMalwareFamilyToSTIXComposite,
)
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_malware import (
    GTIMalwareFamilyToSTIXMalware,
)
from connector.src.custom.mappers.gti_software_toolkits.gti_software_toolkit_to_stix_composite import (
    GTISoftwareToolkitToSTIXComposite,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_composite import (
    GTIThreatActorToSTIXComposite,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.models.gti.gti_attack_technique_id_model import (
    GTIAttackTechniqueIDData,
)
from connector.src.custom.models.gti.gti_malware_family_model import (
    GTIMalwareFamilyData,
)
from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
)
from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
)
from connector.src.utils.converters.generic_converter_config import (
    GenericConverterConfig,
)

GTI_SOFTWARE_TOOLKIT_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="software_toolkits",
    mapper_class=GTISoftwareToolkitToSTIXComposite,
    output_stix_type="tool",
    exception_class=GTISoftwareToolkitConversionError,
    display_name="software toolkits",
    input_model=GTISoftwareToolkitData,
    display_name_singular="software toolkit",
    validate_input=True,
    postprocessing_function=set_context_for("tool"),
)

GTI_SOFTWARE_TOOLKIT_THREAT_ACTOR_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="threat_actors",
    mapper_class=GTIThreatActorToSTIXComposite,
    output_stix_type="intrusion-set",
    exception_class=GTIActorConversionError,
    display_name="threat actors",
    input_model=GTIThreatActorData,
    display_name_singular="threat actor",
    validate_input=True,
    postprocessing_function=uses_relationship(
        GTIThreatActorToSTIXIntrusionSet, "tool", reverse=True
    ),
)

GTI_SOFTWARE_TOOLKIT_MALWARE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="malware_families",
    mapper_class=GTIMalwareFamilyToSTIXComposite,
    output_stix_type="malware",
    exception_class=GTIMalwareConversionError,
    display_name="malware families",
    input_model=GTIMalwareFamilyData,
    display_name_singular="malware family",
    validate_input=True,
    postprocessing_function=related_to_relationship(
        GTIMalwareFamilyToSTIXMalware, "tool"
    ),
)

GTI_SOFTWARE_TOOLKIT_ATTACK_TECHNIQUE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="attack_techniques",
    mapper_class=GTIAttackTechniqueIDsToSTIXAttackPatterns,
    output_stix_type="attack-pattern",
    exception_class=GTITechniqueConversionError,
    display_name="attack techniques",
    input_model=GTIAttackTechniqueIDData,
    display_name_singular="attack technique",
    validate_input=True,
    postprocessing_function=uses_relationship(
        GTIAttackTechniqueIDsToSTIXAttackPatterns, "tool"
    ),
)

SOFTWARE_TOOLKIT_CONVERTER_CONFIGS = {
    "software_toolkit": GTI_SOFTWARE_TOOLKIT_CONVERTER_CONFIG,
    "software_toolkit_threat_actors": GTI_SOFTWARE_TOOLKIT_THREAT_ACTOR_CONVERTER_CONFIG,
    "software_toolkit_malware_families": GTI_SOFTWARE_TOOLKIT_MALWARE_CONVERTER_CONFIG,
    "software_toolkit_attack_techniques": GTI_SOFTWARE_TOOLKIT_ATTACK_TECHNIQUE_CONVERTER_CONFIG,
}
