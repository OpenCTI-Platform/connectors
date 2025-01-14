import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.discovery_url = get_config_variable(
            "TAXII2_DISCOVERY_URL",
            ["taxii2", "discovery_url"],
            self.load,
        )

        self.username = get_config_variable(
            "TAXII2_USERNAME",
            ["taxii2", "username"],
            self.load,
        )

        self.password = get_config_variable(
            "TAXII2_PASSWORD",
            ["taxii2", "password"],
            self.load,
        )

        self.use_token = get_config_variable(
            "TAXII2_USE_TOKEN", ["taxii2", "use_token"], self.load, default=False
        )

        self.token = get_config_variable(
            "TAXII2_TOKEN",
            ["taxii2", "token"],
            self.load,
        )

        self.use_apikey = get_config_variable(
            "TAXII2_USE_APIKEY", ["taxii2", "use_apikey"], self.load, default=False
        )

        self.apikey_key = get_config_variable(
            "TAXII2_APIKEY_KEY",
            ["taxii2", "apikey_key"],
            self.load,
        )

        self.apikey_value = get_config_variable(
            "TAXII2_APIKEY_VALUE",
            ["taxii2", "apikey_value"],
            self.load,
        )

        self.use_cert = get_config_variable(
            "TAXII2_USE_CERT", ["taxii2", "use_cert"], self.load, default=False
        )

        self.cert_path = get_config_variable(
            "TAXII2_CERT_PATH",
            ["taxii2", "cert_path"],
            self.load,
        )

        self.verify_ssl = get_config_variable(
            "TAXII2_VERIFY_SSL",
            ["taxii2", "verify_ssl"],
            self.load,
            default=True,
        )

        self.taxii2v21 = get_config_variable(
            "TAXII2_V21",
            ["taxii2", "v2.1"],
            self.load,
            default=True,
        )

        self.collections = get_config_variable(
            "TAXII2_COLLECTIONS",
            ["taxii2", "collections"],
            self.load,
            default="*.*",
        ).split(",")

        self.initial_history = get_config_variable(
            "TAXII2_INITIAL_HISTORY",
            ["taxii2", "initial_history"],
            self.load,
            default=24,
        )

        self.interval = get_config_variable(
            "TAXII2_INTERVAL",
            ["taxii2", "interval"],
            self.load,
            default=1,
        )

        self.create_indicators = get_config_variable(
            "TAXII2_CREATE_INDICATORS",
            ["taxii2", "create_indicators"],
            self.load,
            default=True,
        )

        self.create_observables = get_config_variable(
            "TAXII2_CREATE_OBSERVABLES",
            ["taxii2", "create_observables"],
            self.load,
            default=True,
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.load,
        )

        self.add_custom_label = get_config_variable(
            "TAXII2_ADD_CUSTOM_LABEL",
            ["taxii2", "add_custom_label"],
            self.load,
            default=False,
        )

        self.custom_label = get_config_variable(
            "TAXII2_CUSTOM_LABEL",
            ["taxii2", "custom_label"],
            self.load,
        )

        self.force_pattern_as_name = get_config_variable(
            "TAXII2_FORCE_PATTERN_AS_NAME",
            ["taxii2", "force_pattern_as_name"],
            self.load,
            default=False,
        )

        self.force_multiple_pattern_name = get_config_variable(
            "TAXII2_FORCE_MULTIPLE_PATTERN_NAME",
            ["taxii2", "force_multiple_pattern_name"],
            self.load,
        )

        self.stix_custom_property_to_label = get_config_variable(
            "TAXII2_STIX_CUSTOM_PROPERTY_TO_LABEL",
            ["taxii2", "stix_custom_property_to_label"],
            self.load,
            default=False,
        )

        self.stix_custom_property = get_config_variable(
            "TAXII2_STIX_CUSTOM_PROPERTY",
            ["taxii2", "stix_custom_property"],
            self.load,
        )

        self.enable_url_query_limit = get_config_variable(
            "TAXII2_ENABLE_URL_QUERY_LIMIT",
            ["taxii2", "enable_url_query_limit"],
            self.load,
            default=False,
        )

        self.url_query_limit = get_config_variable(
            "TAXII2_URL_QUERY_LIMIT",
            ["taxii2", "url_query_limit"],
            self.load,
            default=100,
        )

        self.determine_x_opencti_score_by_label = get_config_variable(
            "TAXII2_DETERMINE_X_OPENCTI_SCORE_BY_LABEL",
            ["taxii2", "determine_x_opencti_score_by_label"],
            self.load,
            default=False,
        )

        self.default_x_opencti_score = get_config_variable(
            "TAXII2_DEFAULT_X_OPENCTI_SCORE",
            ["taxii2", "default_x_opencti_score"],
            self.load,
            default=50,
        )

        self.indicator_high_score_labels = get_config_variable(
            "TAXII2_INDICATOR_HIGH_SCORE_LABELS",
            ["taxii2", "indicator_high_score_labels"],
            self.load,
            default="",
        ).split(",")

        self.indicator_high_score = get_config_variable(
            "TAXII2_INDICATOR_HIGH_SCORE",
            ["taxii2", "indicator_high_score"],
            self.load,
            default=80,
        )

        self.indicator_medium_score_labels = get_config_variable(
            "TAXII2_INDICATOR_MEDIUM_SCORE_LABELS",
            ["taxii2", "indicator_medium_score_labels"],
            self.load,
            default="",
        ).split(",")

        self.indicator_medium_score = get_config_variable(
            "TAXII2_INDICATOR_MEDIUM_SCORE",
            ["taxii2", "indicator_medium_score"],
            self.load,
            default=60,
        )

        self.indicator_low_score_labels = get_config_variable(
            "TAXII2_INDICATOR_LOW_SCORE_LABELS",
            ["taxii2", "indicator_low_score_labels"],
            self.load,
            default="",
        ).split(",")

        self.indicator_low_score = get_config_variable(
            "TAXII2_INDICATOR_LOW_SCORE",
            ["taxii2", "indicator_low_score"],
            self.load,
            default=40,
        )

        self.set_indicator_as_detection = get_config_variable(
            "TAXII2_SET_INDICATOR_AS_DETECTION",
            ["taxii2", "set_indicator_as_detection"],
            self.load,
            default=False,
        )

        self.create_author = get_config_variable(
            "TAXII2_CREATE_AUTHOR",
            ["taxii2", "create_author"],
            self.load,
            default=False,
        )

        self.author_name = get_config_variable(
            "TAXII2_AUTHOR_NAME",
            ["taxii2", "author_name"],
            self.load,
        )

        self.author_description = get_config_variable(
            "TAXII2_AUTHOR_DESCRIPTION",
            ["taxii2", "author_description"],
            self.load,
        )

        self.author_reliability = get_config_variable(
            "TAXII2_AUTHOR_RELIABILITY",
            ["taxii2", "author_reliability"],
            self.load,
        )

        self.exclude_specific_labels = get_config_variable(
            "TAXII2_EXCLUDE_SPECIFIC_LABELS",
            ["taxii2", "exclude_specific_labels"],
            self.load,
            default=False,
        )

        self.labels_to_exclude = get_config_variable(
            "TAXII2_LABELS_TO_EXCLUDE",
            ["taxii2", "labels_to_exclude"],
            self.load,
            default="",
        ).split(",")

        self.replace_characters_in_label = get_config_variable(
            "TAXII2_REPLACE_CHARACTERS_IN_LABEL",
            ["taxii2", "replace_characters_in_label"],
            self.load,
            default=False,
        )

        self.characters_to_replace_in_label = get_config_variable(
            "TAXII2_CHARACTERS_TO_REPLACE_IN_LABEL",
            ["taxii2", "characters_to_replace_in_label"],
            self.load,
            default="",
        ).split(",")

        self.ignore_pattern_types = get_config_variable(
            "TAXII2_IGNORE_PATTERN_TYPES",
            ["taxii2", "ignore_pattern_types"],
            self.load,
            default=False,
        )

        self.pattern_types_to_ignore = get_config_variable(
            "TAXII2_PATTERN_TYPES_TO_IGNORE",
            ["taxii2", "pattern_types_to_ignore"],
            self.load,
            default="",
        ).split(",")

        self.ignore_object_types = get_config_variable(
            "TAXII2_IGNORE_OBJECT_TYPES",
            ["taxii2", "ignore_object_types"],
            self.load,
            default=False,
        )

        self.object_types_to_ignore = get_config_variable(
            "TAXII2_OBJECT_TYPES_TO_IGNORE",
            ["taxii2", "object_types_to_ignore"],
            self.load,
            default="",
        ).split(",")

        self.ignore_specific_patterns = get_config_variable(
            "TAXII2_IGNORE_SPECIFIC_PATTERNS",
            ["taxii2", "ignore_specific_patterns"],
            self.load,
            default=False,
        )

        self.patterns_to_ignore = get_config_variable(
            "TAXII2_PATTERNS_TO_IGNORE",
            ["taxii2", "patterns_to_ignore"],
            self.load,
            default="",
        ).split(",")

        self.ignore_specific_notes = get_config_variable(
            "TAXII2_IGNORE_SPECIFIC_NOTES",
            ["taxii2", "ignore_specific_notes"],
            self.load,
            default=False,
        )

        self.notes_to_ignore = get_config_variable(
            "TAXII2_NOTES_TO_IGNORE",
            ["taxii2", "notes_to_ignore"],
            self.load,
            default="",
        ).split(",")

        self.save_original_indicator_id_to_note = get_config_variable(
            "TAXII2_SAVE_ORIGINAL_INDICATOR_ID_TO_NOTE",
            ["taxii2", "save_original_indicator_id_to_note"],
            self.load,
            default=False,
        )

        self.save_original_indicator_id_abstract = get_config_variable(
            "TAXII2_SAVE_ORIGINAL_INDICATOR_ID_ABSTRACT",
            ["taxii2", "save_original_indicator_id_abstract"],
            self.load,
        )

        self.change_report_status = get_config_variable(
            "TAXII2_CHANGE_REPORT_STATUS",
            ["taxii2", "change_report_status"],
            self.load,
            default=False,
        )

        self.change_report_status_x_opencti_workflow_id = get_config_variable(
            "TAXII2_CHANGE_REPORT_STATUS_X_OPENCTI_WORKFLOW_ID",
            ["taxii2", "change_report_status_x_opencti_workflow_id"],
            self.load,
        )
