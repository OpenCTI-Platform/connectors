from ..utils import parse_stix_pattern


class Observable:
    """
    Represent an Observable (SCO) from OpenCTI.
    All other fields returned by OpenCTI API are discarded.
    """

    def __init__(self, data):
        self.entity_type = data.get("entity_type") or None
        self.id = data.get("id") or None
        self.standard_id = data.get("standard_id") or None
        self.value = data.get("observable_value") or None


class Indicator:
    """
    Represent an Indicator (SDO) from OpenCTI.
    Indicator's observables are from both OpenCTI API and parsed STIX pattern.
    All other fields returned by OpenCTI API are discarded.
    """

    def __init__(self, data):
        self.entity_type = data.get("entity_type") or "Indicator"
        self.id = data.get("id") or None
        self.standard_id = data.get("standard_id") or None
        self.name = data.get("name") or None
        self.description = data.get("description") or None
        self.pattern_type = data.get("pattern_type") or None
        self.pattern = data.get("pattern") or None
        self.confidence = data.get("confidence")
        self.x_opencti_score = data.get("x_opencti_score") or 0
        self.x_mitre_platforms = data.get("x_mitre_platforms") or []

        self.observables = self._parse_observables(data)

    def _parse_observables(self, data) -> list[(str, Observable)]:
        observables = []
        if data.get("observables"):
            for observable in data.get("observables"):
                observables.append((None, Observable(observable)))

        if self.pattern_type == "stix":
            parsed_patterns = parse_stix_pattern(self.pattern)
            for parsed_pattern in parsed_patterns:
                parsed_object_path = parsed_pattern["attribute"].split(".")[0]
                parsed_observable_value = parsed_pattern["value"]

                updated_observable = None
                for index, observable_tuple in enumerate(observables):
                    existing_observable = observable_tuple[1]
                    if existing_observable.value == parsed_observable_value:
                        observables[index] = (parsed_object_path, existing_observable)
                        updated_observable = True
                        break
                if not updated_observable:
                    observables.append(
                        (
                            parsed_object_path,
                            Observable({"observable_value": parsed_observable_value}),
                        )
                    )
        return observables
