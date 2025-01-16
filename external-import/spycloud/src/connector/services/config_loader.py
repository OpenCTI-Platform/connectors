import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pycti import get_config_variable

config_yml_file_path = Path(__file__).parents[2].joinpath("config.yml")
config_yml = (
    yaml.load(open(config_yml_file_path), Loader=yaml.FullLoader)
    if os.path.isfile(config_yml_file_path)
    else {}
)


class OpenCTIConfig:
    @property
    def url(self) -> str:
        return get_config_variable(
            env_var="OPENCTI_URL",
            yaml_path=["opencti", "url"],
            config=config_yml,
            required=True,
        )

    @property
    def token(self) -> str:
        return get_config_variable(
            env_var="OPENCTI_TOKEN",
            yaml_path=["opencti", "token"],
            config=config_yml,
            required=True,
        )


class ConnectorConfig:
    @property
    def id(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_ID",
            yaml_path=["connector", "id"],
            config=config_yml,
            required=True,
        )

    @property
    def type(self) -> str:  # TODO: better typing
        return get_config_variable(
            env_var="CONNECTOR_TYPE",
            yaml_path=["connector", "type"],
            config=config_yml,
            required=True,
        )

    @property
    def name(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_NAME",
            yaml_path=["connector", "name"],
            config=config_yml,
            required=True,
        )

    @property
    def log_level(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_LOG_LEVEL",
            yaml_path=["connector", "log_level"],
            config=config_yml,
            default="info",
            required=True,
        )

    @property
    def scope(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_SCOPE",
            yaml_path=["connector", "scope"],
            config=config_yml,
            default="spycloud",
            required=True,
        )

    @property
    def duration_period(self) -> str:
        return get_config_variable(
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=config_yml,
            required=True,
        )


class SpyCloudConfig:
    @property
    def api_base_url(self) -> str:  # TODO type as URL ?
        raw_url = get_config_variable(
            env_var="SPYCLOUD_API_BASE_URL",
            yaml_path=["spycloud", "api_base_url"],
            config=config_yml,
            required=True,
        )
        return raw_url if raw_url.endswith("/") else f"{raw_url}/"

    @property
    def api_key(self) -> str:
        return get_config_variable(
            env_var="SPYCLOUD_API_KEY",
            yaml_path=["spycloud", "api_key"],
            config=config_yml,
            required=True,
        )

    @property
    def breach_severities(self) -> list[str]:
        # TODO: add enum validation?
        breach_severities_string = get_config_variable(
            env_var="SPYCLOUD_BREACH_SEVERITIES",
            yaml_path=["spycloud", "breach_severities"],
            config=config_yml,
            default="2,5,20,25",
            required=False,
        )
        return [
            string.strip() for string in breach_severities_string.split(",")
        ]  # TODO parse to int ?

    @property
    def watchlist_types(self) -> list[str]:
        # TODO: add enum validation?
        watchlist_types_string = get_config_variable(
            env_var="SPYCLOUD_WATCHLIST_TYPES",
            yaml_path=["spycloud", "watchlist_types"],
            config=config_yml,
            default="email,domain,subdomain,ip",
            required=False,
        )
        return [string.strip() for string in watchlist_types_string.split(",")]

    @property
    def import_start_date(self) -> datetime:
        import_start_date_string = get_config_variable(
            env_var="SPYCLOUD_IMPORT_START_DATE",
            yaml_path=["spycloud", "import_start_date"],
            config=config_yml,
            default="1970-01-01T00:00:00Z",
            required=False,
        )
        return datetime.fromisoformat(import_start_date_string).replace(
            tzinfo=timezone.utc
        )


class ConfigLoader:
    opencti: OpenCTIConfig = OpenCTIConfig()
    connector: ConnectorConfig = ConnectorConfig()
    spycloud: SpyCloudConfig = SpyCloudConfig()

    def to_dict(self) -> dict[str, Any]:
        """Gather configuration settings and return them as a dictionary."""
        return {
            "opencti": {
                "url": self.opencti.url,
                "token": self.opencti.token,
            },
            "connector": {
                "id": self.connector.id,
                "type": self.connector.type,
                "name": self.connector.name,
                "scope": self.connector.scope,
                "log_level": self.connector.log_level,
                "duration": self.connector.duration_period,
                # "queue_threshold": self.connector.queue_threshold,
                # "run_and_terminate": self.connector.run_and_terminate,
                # "send_to_queue": self.connector.send_to_queue,
                # "send_to_directory": self.connector.send_to_directory,
                # "send_to_directory_path": self.connector.send_to_directory_path,
                # "send_to_directory_retention": self.connector.send_to_directory_retention,
            },
            "spycloud": {
                "api_base_url": self.spycloud.api_base_url,
                "api_key": self.spycloud.api_key,
                "breach_severities": self.spycloud.breach_severities,
                "watchlist_types": self.spycloud.watchlist_types,
                "import_start_date": self.spycloud.import_start_date,
                # "marking_definition": self.spycloud.marking_definition,
            },
        }
