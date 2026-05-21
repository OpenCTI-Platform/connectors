"""Channel."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import ChannelType
from pycti import Channel as PyctiChannel
from pycti import CustomObjectChannel
from pydantic import Field


class Channel(BaseIdentifiedEntity):
    """Define a Channel on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Channel.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="A description that provides more details and context about the Channel.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Alternative names used to identify this Channel.",
    )
    channel_types: list[ChannelType] | None = Field(
        default=None,
        description="A set of terms used to describe this Channel.",
    )

    def to_stix2_object(self) -> CustomObjectChannel:
        """Make stix object."""
        return CustomObjectChannel(
            id=PyctiChannel.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            channel_types=self.channel_types,
            **self._common_stix2_properties(),
        )
