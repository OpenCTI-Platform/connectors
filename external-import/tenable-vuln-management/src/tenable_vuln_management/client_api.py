from dateutil import parser
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, Literal

from tenable.io import TenableIO
from tenable.io.exports.iterator import ExportsIterator

from .config_variables import ConfigConnector


if TYPE_CHECKING:
    from pycti import OpenCTIConnectorHelper

SeverityLevelLiteral = Literal["info", "low", "medium", "high", "critical"]


class SeverityLevel(Enum):
    """Model the Severity Levels to interact with Tenable Vulnerability Report endpoint."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @staticmethod
    def levels_above(
        min_level: SeverityLevelLiteral
    ) -> list[str]:
        """Returns a list of string values of all severity levels greater than or equal to the given min_level.

        Args:
            min_level (str): the min vulnerability level.

        Returns:
            (list[str]): the vulnerability levels including min_level

        Examples:
            >>> severities = SeverityLevel.levels_above('medium')
        """
        levels = [level.value for level in SeverityLevel]
        min_index = levels.index(min_level)
        return levels[min_index:]

    @staticmethod
    def index_range(
            min_level: SeverityLevelLiteral
    ) -> list[int]:
        """Returns the index list corresponding to the given min_level and all levels above.

        Args:
            min_level (str): the min vulnerability level.

        Returns:
            (list[int]): the list of indexes corresponding to levels from min_level to the highest.

        Examples:
            >>> indexes = SeverityLevel.index_range('low')
            [1, 2, 3, 4]
        """
        levels = [level.value for level in SeverityLevel]
        min_index = levels.index(min_level)
        return list(range(min_index, len(levels)))


def _get_opencti_version() -> str:
    """Retrieve the current OpenCTI built version.

    The method uses the pycti package version which is aligned with the connector and the OpenCTI platform version.

    Returns (str):
        The current OpenCTI version.

    Notes:
        If running the conector thanks to its docker container, version could also be retrieved from the container
        properties:
            - get the container id from /proc/self/cgroup file
            - call docker API f"{docker_socket_url}/containers/{container_id}/json"
            - parse and extract the image name
            - execute a regex to extract the connector image tag

    Examples:
        >>> version = _get_opencti_version()
    """
    import importlib.metadata

    return importlib.metadata.version(
        "pycti"
    )  # this avoids loading pycti package if not needed


class ConnectorClient:
    def __init__(self, helper: "OpenCTIConnectorHelper", config: ConfigConnector):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.tio_client = TenableIO(
            access_key=self.config.tio_api_access_key,
            secret_key=self.config.tio_api_secret_key,
            url=self.config.tio_api_base_url,
            backoff=self.config.tio_api_backoff,
            retries=self.config.tio_api_retries,
            # Tenable integration best practice.
            # See https://developer.tenable.com/docs/tenableio-integrations [consulted on September 27th, 2024]
            vendor="Filigran",
            product="OpenCTI",
            build=_get_opencti_version(),
        )
        self.helper.log_debug(
            "Tenable Vuln Management API Client User Agent details",
            {
                "user-agent": dict(self.tio_client._session.headers.lower_items()).get(
                    "user-agent"
                )
            },
        )

    @staticmethod
    def safe_call(method) -> Callable[..., Any]:
        @wraps(method)
        def wrapper(self, *args, **kwargs) -> Any:
            try:
                return method(self, *args, **kwargs)
            except Exception as exc:
                self.helper.connector_logger.error(
                    "[API] Error while fetching data.", {"error": str(exc)}
                )
            return None

        return wrapper

    @safe_call
    def get_scans_list(self) -> list[dict[str, Any]]:
        """Synchronously retrieve the scans of Tenable Vulnerability Management Account.

        Returns:
             (list[dict[str, str]]): Performed scans and their last run status:
                * id
                * uuid
                * status
                * name

        References:
            https://developer.tenable.com/reference/scans-list [consulted on September 27th, 2024].
        """
        return [
            {
                "id": scan.get("id"),
                "uuid": scan.get("uuid"),
                "status": scan.get("status"),
                "name": scan.get("name"),
            }
            for scan in self.tio_client.scans.list()
        ]

    @safe_call
    def export_vulnerabilities(self) -> ExportsIterator:
        """Trigger a Vulnerability export process.

        Returns:
            (tenable.io.exports.ExportsIterator): Iterator pointing to triggered export.

        Technical Notes:
            This method implements the use of `since` and `severity` api parameters to reduce the export size.
            The plugin_family, plugin_type, and plugin_id endpoint parameters appeared promising for pre-filtering
            vulnerabilities discovered by plugins that report a CVE (e.g., for an OpenCTI use case). However, after
            testing, iterating through the available plugin information proved to be significantly more time-consuming
            (at least with Tenable Vulnerability Management, as opposed to Tenable Security Center) than first
            retrieving all findings and then filtering them based on their CVE properties.
            For more information, see:
                - https://www.tenable.com/plugins/nessus/families
                - https://community.tenable.com/s/article/Nessus-Plugin-Types-and-Categories?language=en_US
                - https://docs.tenable.com/vulnerability-management/Content/Settings/Tagging/Tags.htm
            [Consulted on September 27th, 2024].
        """
        return self.tio_client.exports.vulns(
            since=int(parser.parse(self.config.tio_export_since).timestamp()),
            severity=SeverityLevel.levels_above(self.config.tio_severity_min_level),
        )

