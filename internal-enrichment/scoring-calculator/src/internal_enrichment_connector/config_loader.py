from internal_enrichment_connector.settings import ConnectorSettings


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load and validate configuration (env vars, config.yml or .env)
        self.settings = ConnectorSettings()
        self._initialize_configurations()

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.opencti_url = str(self.settings.opencti.url)
        self.opencti_token = self.settings.opencti.token.get_secret_value()

        scoring = self.settings.connector_scoring

        # Connector extra parameters
        self.high_priority_labels = scoring.high_priority_labels
        self.medium_priority_labels = scoring.medium_priority_labels
        self.low_priority_labels = scoring.low_priority_labels

        # Strip whitespace on every token so an operator-friendly
        # ``"IPv4-Addr, IPv6-Addr, Domain-Name"`` (with the spaces a
        # human would naturally insert after the commas) matches the
        # canonical bare-comma form ``"IPv4-Addr,IPv6-Addr,..."`` that
        # the rest of the connector compares against.
        self.indicator_type_enrichable = [
            entry.strip()
            for entry in scoring.indicator_type_enrichable.split(",")
            if entry.strip()
        ]

        self.browse_report = scoring.browse_report

        # Threat impact config
        self.threat_impact_score = scoring.threat_impact_score
        self.threat_high_priority = scoring.threat_high_priority
        self.threat_medium_priority = scoring.threat_medium_priority
        self.threat_low_priority = scoring.threat_low_priority

        # Toolbox impact config
        self.toolbox_impact_score = scoring.toolbox_impact_score
        self.toolbox_high_priority = scoring.toolbox_high_priority
        self.toolbox_medium_priority = scoring.toolbox_medium_priority
        self.toolbox_low_priority = scoring.toolbox_low_priority

        # Location impact config
        self.location_impact_score = scoring.location_impact_score
        self.location_high_priority = scoring.location_high_priority
        self.location_medium_priority = scoring.location_medium_priority
        self.location_low_priority = scoring.location_low_priority

        # Sector impact config
        self.sector_impact_score = scoring.sector_impact_score
        self.sector_high_priority = scoring.sector_high_priority
        self.sector_medium_priority = scoring.sector_medium_priority
        self.sector_low_priority = scoring.sector_low_priority

        # TTP impact config
        self.ttp_impact_score = scoring.ttp_impact_score
        self.ttp_high_priority = scoring.ttp_high_priority
        self.ttp_medium_priority = scoring.ttp_medium_priority
        self.ttp_low_priority = scoring.ttp_low_priority

        # Author impact config
        self.author_impact_score = scoring.author_impact_score
        self.author_high_priority = scoring.author_high_priority
        self.author_medium_priority = scoring.author_medium_priority
        self.author_low_priority = scoring.author_low_priority

        # Impact mapping
        self.impact_map = {
            "Threat": {
                "high": self.threat_high_priority,
                "medium": self.threat_medium_priority,
                "low": self.threat_low_priority,
            },
            "Toolbox": {
                "high": self.toolbox_high_priority,
                "medium": self.toolbox_medium_priority,
                "low": self.toolbox_low_priority,
            },
            "Location": {
                "high": self.location_high_priority,
                "medium": self.location_medium_priority,
                "low": self.location_low_priority,
            },
            "Sector": {
                "high": self.sector_high_priority,
                "medium": self.sector_medium_priority,
                "low": self.sector_low_priority,
            },
            "TTP": {
                "high": self.ttp_high_priority,
                "medium": self.ttp_medium_priority,
                "low": self.ttp_low_priority,
            },
            "Author": {
                "high": self.author_high_priority,
                "medium": self.author_medium_priority,
                "low": self.author_low_priority,
            },
        }

        # Enable flags
        self.impact_enabled = {
            "Threat": self.threat_impact_score,
            "Toolbox": self.toolbox_impact_score,
            "Location": self.location_impact_score,
            "Sector": self.sector_impact_score,
            "TTP": self.ttp_impact_score,
            "Author": self.author_impact_score,
        }
