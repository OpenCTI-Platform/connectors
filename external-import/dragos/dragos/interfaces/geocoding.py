"""Define the Geocoding interface."""

from abc import ABC, abstractmethod
from typing import Any, Optional

from dragos.interfaces.common import DataRetrievalError, FrozenBaseModel
from pydantic import (
    Field,
    ValidationError,
)


class GeocodingRetrievalError(DataRetrievalError):
    """Error raised when geocoding retrieval fails."""


class BaseGeolocation(FrozenBaseModel):
    """Base class for Geolocation."""

    def __init__(self, *args: Any, **kwargs: dict[str, Any]) -> None:
        """Initialize the Geolocation."""
        try:
            FrozenBaseModel.__init__(self, *args, **kwargs)
        except ValidationError as e:
            raise GeocodingRetrievalError("Failed to retrieve geolocation") from e


class Country(BaseGeolocation):
    """Define Country."""

    name: str = Field(..., description="The country name.", min_length=1)


class Region(BaseGeolocation):
    """DEfine Region."""

    name: str = Field(..., description="The region name.", min_length=1)


class Area(BaseGeolocation):
    """DEfine Area."""

    name: str = Field(..., description="The area name.", min_length=1)


class City(BaseGeolocation):
    """Define City."""

    name: str = Field(..., description="The city name.", min_length=1)


class Position(BaseGeolocation):
    """Define Position."""

    name: str = Field(..., description="The position name.", min_length=1)
    latitude: Optional[float] = Field(
        None, description="The position latitude in WGS84."
    )
    longitude: Optional[float] = Field(
        None, description="The position longitude in WGS84."
    )


class Geocoding(ABC):
    """Interface for Geocoding data.

    This class should be implemented to be used as a geocoding service.

    Examples:
        >>> from dragos.interfaces.geocoding import Geocoding, GeoRetrievalError
        >>> import requests
        >>> import logging
        >>> from typing import Optional
        >>> logger = logging.getLogger(__name__)
        >>> class MyGeocoding(Geocoding):
        ...     def __init__(self: "MyGeocoding", url: str, creds: dict[str, str]) -> None:
        ...         '''Initialize the geocoding service.'''
        ...         self.headers = {"Authorization": f"Bearer {creds['token']}"}
        ...         self.url = url
        ...
        ...     def _call_geocoding_api(self: "MyGeocoding", name: str) -> requests.Response:
        ...         '''Call the geocoding API.'''
        ...         return requests.get(f"{self.url}/search?name={name}", headers=self.headers)
        ...
        ...     def find_from_name(self: "MyGeocoding", name: str) -> Optional[Country | Region | Area | City | Position]:
        ...         '''Retrieve geocoding data.'''
        ...         try:
        ...             response = self._call_geocoding_api(name)
        ...             response.raise_for_status()
        ...             data = response.json()
        ...             if data["type"] == "Country":
        ...                 return Country(name=data["name"])
        ...             else:
        ...                 logger.info(f"Unsupported geocoding data type with MyGeocoding service: {data['type']}")
        ...                 return None
        ...         except requests.exceptions.RequestException as e:
        ...             raise GeoRetrievalError("Failed to retrieve geocoding data") from e

    """

    @abstractmethod
    def find_from_name(
        self: "Geocoding", name: str
    ) -> Optional[Country | Region | Area | City | Position]:
        """Retrieve geocoding data."""
