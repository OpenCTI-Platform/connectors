from models.configs.config_loader import ConfigLoader


class ConfigCrowdstrike:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        # Load configuration using the new config loader
        self.config = ConfigLoader()

        # Initialize OpenCTI helper configuration for backward compatibility
        self.load = self.config.model_dump_pycti()
        self._initialize_configurations()

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables - mapped from new config loader
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = self.config.connector.duration_period

        # Crowdstrike configurations
        self.base_url = str(self.config.crowdstrike.base_url)
        self.client_id = self.config.crowdstrike.client_id.get_secret_value()
        self.client_secret = self.config.crowdstrike.client_secret.get_secret_value()
        self.tlp = self.config.crowdstrike.tlp
        self.create_observables = self.config.crowdstrike.create_observables
        self.create_indicators = self.config.crowdstrike.create_indicators

        # MITRE ATT&CK Enterprise dataset lookup (used for technique ID resolution)
        # Pin a specific ATT&CK version for deterministic mapping; allow URL override for airgapped/mirrors.
        self.attack_version = self.config.crowdstrike.attack_version
        self.attack_enterprise_url = self.config.crowdstrike.attack_enterprise_url

        # Convert list to comma-separated string for backward compatibility
        scopes_list = self.config.crowdstrike.scopes
        self.scopes = ",".join(scopes_list) if scopes_list else None

        self.actor_start_timestamp = self.config.crowdstrike.actor_start_timestamp
        self.malware_start_timestamp = self.config.crowdstrike.malware_start_timestamp
        self.report_start_timestamp = self.config.crowdstrike.report_start_timestamp
        self.report_status = self.config.crowdstrike.report_status

        # Convert lists to comma-separated strings for backward compatibility
        report_include_types = self.config.crowdstrike.report_include_types
        self.report_include_types = (
            ",".join(report_include_types) if report_include_types else None
        )

        report_target_industries = self.config.crowdstrike.report_target_industries
        self.report_target_industries = (
            ",".join(report_target_industries) if report_target_industries else None
        )

        self.report_type = self.config.crowdstrike.report_type
        self.report_guess_malware = self.config.crowdstrike.report_guess_malware
        self.report_guess_relations = self.config.crowdstrike.report_guess_relations
        self.indicator_start_timestamp = (
            self.config.crowdstrike.indicator_start_timestamp
        )

        indicator_exclude_types = self.config.crowdstrike.indicator_exclude_types
        self.indicator_exclude_types = (
            ",".join(indicator_exclude_types) if indicator_exclude_types else None
        )

        self.default_x_opencti_score = self.config.crowdstrike.default_x_opencti_score
        self.indicator_low_score = self.config.crowdstrike.indicator_low_score

        indicator_low_score_labels = self.config.crowdstrike.indicator_low_score_labels
        self.indicator_low_score_labels = (
            ",".join(indicator_low_score_labels) if indicator_low_score_labels else None
        )

        self.indicator_medium_score = self.config.crowdstrike.indicator_medium_score

        indicator_medium_score_labels = (
            self.config.crowdstrike.indicator_medium_score_labels
        )
        self.indicator_medium_score_labels = (
            ",".join(indicator_medium_score_labels)
            if indicator_medium_score_labels
            else None
        )

        self.indicator_high_score = self.config.crowdstrike.indicator_high_score

        indicator_high_score_labels = (
            self.config.crowdstrike.indicator_high_score_labels
        )
        self.indicator_high_score_labels = (
            ",".join(indicator_high_score_labels)
            if indicator_high_score_labels
            else None
        )

        indicator_unwanted_labels = self.config.crowdstrike.indicator_unwanted_labels
        self.indicator_unwanted_labels = (
            ",".join(indicator_unwanted_labels).lower()
            if indicator_unwanted_labels
            else None
        )

        self.interval_sec = self.config.crowdstrike.interval_sec
        self.no_file_trigger_import = self.config.crowdstrike.no_file_trigger_import
        self.vulnerability_start_timestamp = (
            self.config.crowdstrike.vulnerability_start_timestamp
        )
