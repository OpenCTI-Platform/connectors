"""Implement Geocoding Interface to provide Geolocation data to the connector from OpenCTI platform."""

from logging import getLogger
from typing import TYPE_CHECKING, Any, Optional

from dragos.interfaces.geocoding import (
    Area,
    City,
    Country,
    Geocoding,
    GeocodingRetrievalError,
    Position,
    Region,
)

if TYPE_CHECKING:
    from pycti.api.opencti_api_client import (  # type: ignore[import-untyped]
        OpenCTIApiClient,
    )

logger = getLogger(__name__)


class OctiGeocoding(Geocoding):
    """Provide Geolocation data to the connector from OpenCTI platform."""

    def __init__(self: "OctiGeocoding", api_client: "OpenCTIApiClient") -> None:
        """Initialize the Geocoding Adapter."""
        self._api_client = api_client

    def _search_by_name_and_alias(self: "OctiGeocoding", name: str) -> list[Any]:
        """Search for geocoding data."""
        return list(
            self._api_client.stix_domain_object.list(
                types=["Country", "Region", "City", "Position", "Administrative-Area"],
                filters={
                    "mode": "or",
                    "filters": [
                        {
                            "key": [
                                "name",
                                "x_opencti_aliases",
                            ],
                            "values": [name],
                        }
                    ],
                    "filterGroups": [],
                },
                # search = name
                # first
                # after
                # order_by
                # order_mode
                # custom_attributes
                # get_all
                # with_pagination
                # with_files
            )
        )

    def find_from_name(
        self: "OctiGeocoding", name: str
    ) -> Optional[Country | Region | Area | City | Position]:
        """Retrieve geocoding data.

        Examples:
            >>> from pycti import OpenCTIApiClient
            >>> from dragos.adapters.geocoding.octi import OctiGeocoding
            >>> client = OpenCTIApiClient(url="https://demo.opencti.io", token="YOUR_TOKEN")
            >>> geocoding = OctiGeocoding(client)
            >>> geolocation = geocoding.find_from_name("France")

        """
        results = self._search_by_name_and_alias(name)
        count = len(results)
        if count > 1:
            logger.info(
                f"Multiple results found for {name}. Unable to determine the correct geolocation."
            )
            return None
        if count == 0:
            logger.info(f"No results found for {name}.")
            return None

        entity = dict(results[0])

        entity_type = entity.get("entity_type")
        try:
            match entity_type:
                case "Country":
                    return Country(name=entity["name"])
                case "Region":
                    return Region(name=entity["name"])
                case "City":
                    return City(name=entity["name"])
                case "Position":
                    return Position(
                        name=entity["name"],
                        latitude=entity["latitude"],
                        longitude=entity["longitude"],
                    )
                case "Administrative-Area":
                    # No name attribute returned for Administrative-Area entity.
                    # return Area(name=entity["name"])
                    logger.info(
                        "Administrative-Area entity type not supported. Unable to determine the correct geolocation"
                    )
                    return None
                case _:
                    raise NotImplementedError(f"Unsupported entity type {entity_type}")

        except (KeyError, NotImplementedError) as e:
            raise GeocodingRetrievalError(
                f"Failed to retrieve geolocation data for {name}"
            ) from e
