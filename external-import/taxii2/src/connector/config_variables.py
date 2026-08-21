from pydantic import SecretStr

from .settings import ConnectorSettings


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load and validate the configuration (env vars, `.env` file or `config.yml`)
        self.settings = ConnectorSettings()
        self._initialize_configurations()

    def to_helper_config(self) -> dict:
        """
        Convert the validated settings into a valid config dict for `pycti.OpenCTIConnectorHelper`
        :return: Configuration dictionary
        """
        return self.settings.to_helper_config()

    @staticmethod
    def _reveal(secret: SecretStr | None) -> str | None:
        """
        Reveal the plain value of an optional secret
        :param secret: The secret to reveal, if any
        :return: The plain secret value or None
        """
        return secret.get_secret_value() if secret is not None else None

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        connector = self.settings.connector
        taxii2 = self.settings.taxii2

        # OpenCTI configurations
        self.duration_period = connector.duration_period

        # Connector extra parameters
        self.discovery_url = taxii2.discovery_url

        self.username = taxii2.username

        self.password = self._reveal(taxii2.password)

        self.use_token = taxii2.use_token

        self.token = self._reveal(taxii2.token)

        self.use_apikey = taxii2.use_apikey

        self.apikey_key = taxii2.apikey_key

        self.apikey_value = self._reveal(taxii2.apikey_value)

        self.use_cert = taxii2.use_cert

        self.cert_path = taxii2.cert_path

        self.verify_ssl = taxii2.verify_ssl

        self.taxii2v21 = taxii2.v21

        self.collections = taxii2.collections

        self.initial_history = taxii2.initial_history

        self.interval = taxii2.interval

        self.create_indicators = taxii2.create_indicators

        self.create_observables = taxii2.create_observables

        self.add_custom_label = taxii2.add_custom_label

        self.custom_label = taxii2.custom_label

        self.force_pattern_as_name = taxii2.force_pattern_as_name

        self.force_multiple_pattern_name = taxii2.force_multiple_pattern_name

        self.stix_custom_property_to_label = taxii2.stix_custom_property_to_label

        self.stix_custom_property = taxii2.stix_custom_property

        self.enable_url_query_limit = taxii2.enable_url_query_limit

        self.url_query_limit = taxii2.url_query_limit

        self.determine_x_opencti_score_by_label = (
            taxii2.determine_x_opencti_score_by_label
        )

        self.default_x_opencti_score = taxii2.default_x_opencti_score

        self.indicator_high_score_labels = taxii2.indicator_high_score_labels

        self.indicator_high_score = taxii2.indicator_high_score

        self.indicator_medium_score_labels = taxii2.indicator_medium_score_labels

        self.indicator_medium_score = taxii2.indicator_medium_score

        self.indicator_low_score_labels = taxii2.indicator_low_score_labels

        self.indicator_low_score = taxii2.indicator_low_score

        self.set_indicator_as_detection = taxii2.set_indicator_as_detection

        self.create_author = taxii2.create_author

        self.author_name = taxii2.author_name

        self.author_description = taxii2.author_description

        self.author_reliability = taxii2.author_reliability

        self.exclude_specific_labels = taxii2.exclude_specific_labels

        self.labels_to_exclude = taxii2.labels_to_exclude

        self.replace_characters_in_label = taxii2.replace_characters_in_label

        self.characters_to_replace_in_label = taxii2.characters_to_replace_in_label

        self.ignore_pattern_types = taxii2.ignore_pattern_types

        self.pattern_types_to_ignore = taxii2.pattern_types_to_ignore

        self.ignore_object_types = taxii2.ignore_object_types

        self.object_types_to_ignore = taxii2.object_types_to_ignore

        self.ignore_specific_patterns = taxii2.ignore_specific_patterns

        self.patterns_to_ignore = taxii2.patterns_to_ignore

        self.ignore_specific_notes = taxii2.ignore_specific_notes

        self.notes_to_ignore = taxii2.notes_to_ignore

        self.save_original_indicator_id_to_note = (
            taxii2.save_original_indicator_id_to_note
        )

        self.save_original_indicator_id_abstract = (
            taxii2.save_original_indicator_id_abstract
        )

        self.change_report_status = taxii2.change_report_status

        self.change_report_status_x_opencti_workflow_id = (
            taxii2.change_report_status_x_opencti_workflow_id
        )
