from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class StreamConnectorConfig(BaseStreamConnectorConfig):
    """
    Override the `BaseStreamConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `STREAM`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4e4988ea-74d4-485c-9517-796edbcb3a8c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Jira",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )


class JiraConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `JiraConnector`.
    """

    url: str = Field(
        description="URL to Jira server (e.g., https://yourinstance.atlassian.net).",
    )
    ssl_verify: bool = Field(
        description="Whether to verify SSL certificates.",
        default=True,
    )
    login_email: str = Field(
        description="Email for Jira account with API access.",
    )
    api_token: SecretStr = Field(
        description="API token for Jira authentication.",
    )
    project_key: str = Field(
        description="Jira project key (not name) for issue creation.",
    )
    issue_type_name: str = Field(
        description="Issue type to create (Epic, Task, etc.).",
        default="Task",
    )
    custom_fields_keys: str = Field(
        description="Comma-separated custom field IDs (e.g., customfield_10039).",
        default="",
    )
    custom_fields_values: str = Field(
        description="Comma-separated values for custom fields (same order).",
        default="",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `StreamConnectorConfig` and `JiraConfig`.
    """

    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    jira: JiraConfig = Field(default_factory=JiraConfig)
