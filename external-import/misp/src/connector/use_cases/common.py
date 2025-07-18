import pycti
import stix2

TLP_CLEAR = stix2.MarkingDefinition(
    id=pycti.MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="TLP",
    x_opencti_definition="TLP:CLEAR",
)

TLP_AMBER_STRICT = stix2.MarkingDefinition(
    id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="TLP",
    x_opencti_definition="TLP:AMBER+STRICT",
)

PAP_CLEAR = stix2.MarkingDefinition(
    id=pycti.MarkingDefinition.generate_id("PAP", "PAP:CLEAR"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:CLEAR",
)

PAP_GREEN = stix2.MarkingDefinition(
    id=pycti.MarkingDefinition.generate_id("PAP", "PAP:GREEN"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:GREEN",
)

PAP_AMBER = stix2.MarkingDefinition(
    id=pycti.MarkingDefinition.generate_id("PAP", "PAP:AMBER"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:AMBER",
)

PAP_RED = stix2.MarkingDefinition(
    id=pycti.MarkingDefinition.generate_id("PAP", "PAP:RED"),
    definition_type="statement",
    definition={"statement": "custom"},
    allow_custom=True,
    x_opencti_definition_type="PAP",
    x_opencti_definition="PAP:RED",
)


class ConverterError(Exception):
    """Custom exception for conversion errors."""


class ConverterConfigError(Exception):
    """Custom exception for converter config errors."""


class ConverterConfig:
    def __init__(
        self,
        report_type: str = "misp-event",
        report_description_attribute_filters: dict = {},
        external_reference_base_url: str = None,
        get_author_from_tags: bool = False,
        get_markings_from_tags: bool = False,
        get_labels_from_tags: bool = True,
        get_associated_files_from_attributes: bool = False,
        get_observables_from_objects: bool = False,
        guess_threats_from_tags: bool = False,
        convert_event_to_report: bool = True,
        convert_attribute_to_indicator: bool = True,
        convert_attribute_to_observable: bool = True,
        convert_unsupported_objects_to_custom_observables: bool = True,
        propagate_report_labels: bool = False,
        original_tags_to_keep_as_labels: list[str] = [],
    ):
        self.report_type = report_type
        self.report_description_attribute_filters = report_description_attribute_filters
        self.external_reference_base_url = external_reference_base_url
        self.get_author_from_tags = get_author_from_tags
        self.get_markings_from_tags = get_markings_from_tags
        self.get_labels_from_tags = get_labels_from_tags
        self.get_associated_files_from_attributes = get_associated_files_from_attributes
        self.get_observables_from_objects = get_observables_from_objects
        self.guess_threats_from_tags = guess_threats_from_tags
        self.convert_event_to_report = convert_event_to_report
        self.convert_attribute_to_indicator = convert_attribute_to_indicator
        self.convert_attribute_to_observable = convert_attribute_to_observable
        self.convert_unsupported_objects_to_custom_observables = (
            convert_unsupported_objects_to_custom_observables
        )
        self.propagate_report_labels = propagate_report_labels
        self.original_tags_to_keep_as_labels = original_tags_to_keep_as_labels
