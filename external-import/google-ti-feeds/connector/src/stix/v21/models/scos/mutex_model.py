"""The module defines the MutexModel class, which represents a STIX 2.1 Mutex object."""

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
# noinspection PyProtectedMember
from stix2.v21 import Mutex, _STIXBase21  # type: ignore


class MutexModel(BaseSCOModel):
    """Model representing a Mutex in STIX 2.1 format."""

    name: str = Field(..., description="The name of the mutex object as observed.")

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Mutex(**self.model_dump(exclude_none=True))
