from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.settings.deprecations import DeprecatedField
from pydantic import Field


class BeaconBeagleConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration with BeaconBeagle defaults."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="13cc97e9-a3c7-4b06-8c8e-e2e8d85e1a98",
    )
    name: str = Field(
        description="The name of the connector.",
        default="BeaconBeagle",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["beaconbeagle"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=2),
    )


class BeaconBeagleConfig(BaseConfigModel):
    """Config fields specific to the BeaconBeagle connector."""

    url: str = Field(
        description="The BeaconBeagle C2 list URL.",
        default=(
            "https://beaconbeagle.com/api/v1/c2?q=&protocol=&port=&min_endpoints=0"
            "&first_after=&first_before=&last_after=&last_before="
            "&sort=firsttime&order=desc"
        ),
    )
    add_urls: bool = Field(
        description="Save URLs from BeaconBeagle into OpenCTI.",
        default=False,
    )
    add_useragent: bool = Field(
        description="Save User-Agent strings as observables.",
        default=False,
    )
    link_tool: str = Field(
        description=(
            "Tool name (e.g. 'CobaltStrike') to link observables to. "
            "Leave empty to skip the link."
        ),
        default="",
    )
    link_ap: str = Field(
        description=(
            "Attack-pattern reference. Either a plain name or '<MITRE_ID> <name>' "
            "(e.g. 'T1071 Standard Application Layer Protocol'). "
            "Leave empty to skip."
        ),
        default="",
    )
    link_country: bool = Field(
        description="Create a Country location for each C2 IP and link it.",
        default=False,
    )
    link_bgpas: bool = Field(
        description=(
            "Create an Autonomous-System observable for each C2 IP and link it."
        ),
        default=False,
    )
    search_bgpas: bool = Field(
        description=(
            "Fall back to 'whois -h bgp.tools' when the BeaconBeagle payload is "
            "missing the AS / country fields. Generates outbound traffic to "
            "bgp.tools."
        ),
        default=False,
    )
    link_watermark_txt: str = Field(
        description=(
            "Suffix appended to the Text observable that tracks CobaltStrike "
            "licence watermarks. Leave empty to disable."
        ),
        default="",
    )
    links_duration: int = Field(
        description=(
            "Duration in hours used as the indicator valid_from-valid_until "
            "window when BeaconBeagle does not provide a lasttime for a C2 entry."
        ),
        default=24,
    )
    interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(hours=int(x)),
    )
    marking: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Marking definition applied on every produced object.",
        default="TLP:GREEN",
    )

    # Former config.yml keys, renamed to match the documented environment
    # variables (BEACONBEAGLE_MARKING, BEACONBEAGLE_LINK_WATERMARK_TXT).
    marking_definition: str | None = DeprecatedField(
        deprecated="Use 'marking' instead.",
        new_namespaced_var="marking",
    )
    link_watermark: str | None = DeprecatedField(
        deprecated="Use 'link_watermark_txt' instead.",
        new_namespaced_var="link_watermark_txt",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the BeaconBeagle connector."""

    connector: BeaconBeagleConnectorConfig = Field(
        default_factory=BeaconBeagleConnectorConfig
    )
    beaconbeagle: BeaconBeagleConfig = Field(default_factory=BeaconBeagleConfig)
