"""Configuration loader for the PGL Yoyo Connector."""

from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    """Configuration loader for the PGL Yoyo Connector."""

    def __init__(self, config=None):
        """
        Initialize the connector with necessary configurations.

        Accept an optional `config` mapping. If `config` is None, load
        defaults from `config.yml.sample` and merge with `config.yml` if
        present. This follows the project convention and allows environment
        overrides via `get_config_variable`.
        """

        # Load config from file when not provided
        if config is None:
            base_dir = Path(__file__).parents[1]
            config_path = base_dir.joinpath("config.yml")

            # Load user-provided config if present
            cfg = {}
            if config_path.is_file():
                try:
                    with config_path.open(encoding="utf-8") as fh:
                        cfg = yaml.safe_load(fh) or {}
                except (yaml.YAMLError, OSError):
                    cfg = {}

            # mypy-friendly assignment
            config = cfg  # type: ignore[misc]

        # coerce to a plain dict for get_config_variable which expects a Dict
        config = dict(config) if config is not None else {}

        # Store merged config and initialize
        self.load = config
        self._initialize_configurations()

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI / connector configurations
        config = self.load

        # The sample uses `connector.interval` (seconds). Map that to the
        # project convention `connector.duration_period` while still allowing
        # environment overrides.
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            config,
            default=config.get("connector", {}).get("interval", 43200),
        )

        # Connector metadata and operational flags (defaults from sample)
        self.name = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            config,
            default=config.get("connector", {}).get(
                "name", "PGL Yoyo Ad Server Blocklist"
            ),
        )

        self.scope = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            config,
            default=config.get("connector", {}).get("scope", "observable"),
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING",
            ["connector", "update_existing_data"],
            config,
            default=config.get("connector", {}).get("update_existing_data", True),
        )

        self.run_and_terminate = get_config_variable(
            "CONNECTOR_RUN_AND_TERMINATE",
            ["connector", "run_and_terminate"],
            config,
            default=config.get("connector", {}).get("run_and_terminate", False),
        )

        # Confidence level used by the connector; ensure a sensible default is
        # available even when `config.yml` is not provided.
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            default=config.get("connector", {}).get("confidence_level", 50),
        )

        # Mirror into self.load so existing code that reads `conf.load[...]`
        # continues to work when expecting connector.confidence_level.
        if "connector" not in self.load:
            self.load["connector"] = {}
        self.load["connector"]["confidence_level"] = self.confidence_level

        # PGL connector specific defaults (sourced from config.yml.sample)
        # Use environment variables to override where appropriate
        # (project convention)
        self.bundle_mode = get_config_variable(
            "PGL_BUNDLE_MODE",
            ["pgl", "bundle_mode"],
            config,
            default=True,
        )

        self.report_per_run = get_config_variable(
            "PGL_REPORT_PER_RUN",
            ["pgl", "report_per_run"],
            config,
            default=True,
        )

        self.identity_name = get_config_variable(
            "PGL_IDENTITY_NAME",
            ["pgl", "identity_name"],
            config,
            default="Peter Lowe (PGL Blocklist)",
        )

        self.identity_class = get_config_variable(
            "PGL_IDENTITY_CLASS",
            ["pgl", "identity_class"],
            config,
            default="organization",
        )

        self.identity_description = get_config_variable(
            "PGL_IDENTITY_DESCRIPTION",
            ["pgl", "identity_description"],
            config,
            default=(
                "Curated ad server & tracking blocklist maintained by "
                "Peter G. Lowe (yoyo.org)."
            ),
        )

        self.identity_id = get_config_variable(
            "PGL_IDENTITY_ID",
            ["pgl", "identity_id"],
            config,
            default="",
        )

        self.feeds = self.load.get("pgl", {}).get("feeds")
        if not isinstance(self.feeds, list) or not self.feeds:
            self.feeds = [
                {
                    "name": "PGL - Trackers (Hostnames)",
                    "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&showintro=0&onlytrackers=1&mimetype=plaintext",
                    "type": "Domain-Name",
                    "labels": ["OSINT", "Blocklist", "AdTech", "Tracker"],
                },
                {
                    "name": "PGL - Trackers (IPs)",
                    "url": "https://pgl.yoyo.org/adservers/iplist.php?ipformat=plain&showintro=0&onlytrackers=1&mimetype=plaintext",
                    "type": "IPv4-Addr",
                    "labels": ["OSINT", "Blocklist", "AdTech", "Tracker"],
                },
                {
                    "name": "PGL - Non-Trackers (Hostnames)",
                    "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&showintro=0&notrackers=1&mimetype=plaintext",
                    "type": "Domain-Name",
                    "labels": ["OSINT", "Blocklist", "AdTech", "Non-Tracker"],
                },
                {
                    "name": "PGL - Non-Trackers (IPs)",
                    "url": "https://pgl.yoyo.org/adservers/iplist.php?ipformat=plain&showintro=0&notrackers=1&mimetype=plaintext",
                    "type": "IPv4-Addr",
                    "labels": ["OSINT", "Blocklist", "AdTech", "Non-Tracker"],
                },
            ]

    def __getitem__(self, item):
        """Allow dict-like access to configuration items."""
        return self.load.get(item)

    def get(self, item, default=None):
        """Get configuration item with optional default."""
        return self.load.get(item, default)
