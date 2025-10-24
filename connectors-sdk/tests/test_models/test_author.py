from typing import OrderedDict

import pytest
import stix2
import stix2.properties
from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from pydantic import Field


@pytest.fixture
def implemented_author():
    """Fixture to provide an implemented Author."""

    class ImplementedAuthor(BaseAuthorEntity):
        """A concrete implementation of Author for testing."""

        name: str
        email: str | None = Field(None, description="Email of the author.")

        def to_stix2_object(self) -> stix2.v21._STIXBase21:
            class DummyStixObject(stix2.v21._STIXBase21):
                _properties = OrderedDict(
                    [
                        ("spec_version", stix2.properties.StringProperty(fixed="2.1")),
                        ("name", stix2.properties.StringProperty()),
                        (
                            "id",
                            stix2.properties.IDProperty(
                                type="author", spec_version="2.1"
                            ),
                        ),
                    ]
                )

            return DummyStixObject(id=f"author--{self.name}", name=self.name)

    return ImplementedAuthor


def test_author_should_be_a__base_identified_entity(implemented_author):
    """Test that Author is a BaseIdentifiedEntity."""
    # Given an implemented Author
    author_class = implemented_author
    # When checking the class inheritance
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(author_class, BaseIdentifiedObject)
