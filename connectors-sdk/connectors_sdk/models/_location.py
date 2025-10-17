"""Location."""

from stix2.v21 import Location as Stix2Location


class Location(Stix2Location):  # type: ignore[misc]  # stix2 does not provide stubs
    """Override stix2 Location to skip some constraints incompatible with OpenCTI Location entities."""

    def _check_object_constraints(self) -> None:
        """Override _check_object_constraints method."""
        location_type = (self.x_opencti_location_type or "").lower()
        if location_type in ["administrative-area", "city", "position"]:
            self._check_properties_dependency(["latitude"], ["longitude"])
            self._check_properties_dependency(["longitude"], ["latitude"])

            # Skip (region OR country OR (latitude AND longitude)) check because all of them are optional on OpenCTI
            # even though at least one of them is required in the STIX2.1 Location spec
            #
            # Skip (precision AND (latitude OR longitude)) check because OpenCTI does not handle precision at all
        else:
            super()._check_object_constraints()
