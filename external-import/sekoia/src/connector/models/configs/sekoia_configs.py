from typing import Annotated, Optional

from pydantic import Field, HttpUrl, PlainSerializer, PositiveInt, SecretStr
from src.connector.models.configs import ConfigBaseSettings

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class _ConfigLoaderSekoia(ConfigBaseSettings):
    """Interface for loading Sekoia dedicated configuration."""

    # Config Loader
    api_key: SecretStr = Field(
        description="API key used to authenticate requests to the Sekoia service.",
    )
    base_url: str = Field(
        default="https://api.sekoia.io",
        description="Base URL for accessing the Sekoia API.",
    )
    collection: str = Field(
        default="d6092c37-d8d7-45c3-8aff-c4dc26030608",
        description="Allows you to specify the collection to query in order to retrieve or manage indicators of compromise.",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="The date to start consuming data from. May be in the formats YYYY-MM-DD or YYYY-MM-DDT00:00:00.",
    )
    limit: PositiveInt = Field(
        default=200,
        description="The number of elements to fetch in each request. Defaults to 200, maximum 2000.",
    )
    create_observables: bool = Field(
        default=True,
        description="Create observables from indicators.",
    )
    import_source_list: bool = Field(
        default=False,
        description="Create the list of sources observed by Sekoia as label.",
    )
    import_ioc_relationships: bool = Field(
        default=True,
        description="Import IOCs relationships and related objects.",
    )
