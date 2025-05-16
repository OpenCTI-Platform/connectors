"""The module defines the MutexModel class, which represents a STIX 2.1 Mutex object."""

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import Mutex, _STIXBase21  # type: ignore


class MutexModel(BaseSCOModel):
    """Model representing a Mutex in STIX 2.1 format."""

    name: str = Field(..., description="The name of the mutex object as observed.")

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Mutex(**self.model_dump(exclude_none=True))


def test_mutex_model() -> None:
    """Test function to demonstrate the usage of MutexModel."""
    from uuid import uuid4

    # === Minimal Mutex ===
    minimal = MutexModel(
        type="mutex",
        spec_version="2.1",
        id=f"mutex--{uuid4()}",
        name="Global\\Hydra_Lock",
    )

    print("=== MINIMAL MUTEX ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Mutex ===
    full = MutexModel(
        type="mutex",
        spec_version="2.1",
        id=f"mutex--{uuid4()}",
        name="Global\\APT_Execution_Guard",
    )

    print("\n=== FULL MUTEX ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_mutex_model()
