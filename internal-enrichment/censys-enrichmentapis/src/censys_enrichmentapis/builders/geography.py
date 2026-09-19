from censys_enrichmentapis.builders.base import AreaStixBuilder
from censys_platform import Coordinates
from connectors_sdk.models import (
    AdministrativeArea,
    City,
    Country,
    Reference,
    Region,
    Relationship,
)
from connectors_sdk.models.enums import RelationshipType


class GeographyStixBuilder(AreaStixBuilder):
    def add_city(self, observable: Reference, name: str | None) -> None:
        if not name:
            return

        city = City(name=name, **self.common_props)
        self.bundle.extend(
            [
                city,
                Relationship(
                    source=observable,
                    target=city,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )

    def add_country(self, observable: Reference, name: str | None) -> Country | None:
        if not name:
            return None

        country = Country(name=name, **self.common_props)
        self.bundle.extend(
            [
                country,
                Relationship(
                    source=observable,
                    target=country,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )
        return country

    def add_region(self, observable: Reference, name: str | None) -> None:
        if not name:
            return

        region = Region(name=name, **self.common_props)
        self.bundle.extend(
            [
                region,
                Relationship(
                    source=observable,
                    target=region,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )

    def add_administrative_area(
        self,
        observable: Reference,
        name: str | None,
        coordinates: Coordinates | None,
    ) -> None:
        if not name:
            return

        administrative_area = (
            AdministrativeArea(
                name=name,
                latitude=coordinates.latitude,
                longitude=coordinates.longitude,
                **self.common_props,
            )
            if coordinates
            else AdministrativeArea(name=name, **self.common_props)
        )
        self.bundle.extend(
            [
                administrative_area,
                Relationship(
                    source=observable,
                    target=administrative_area,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )
