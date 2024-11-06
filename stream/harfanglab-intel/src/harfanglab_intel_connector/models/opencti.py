class Indicator:
    """
    Represent an Indicator (SDO) from OpenCTI.
    All other fields returned by OpenCTI API are discarded.
    """

    def __init__(self, data):
        self.entity_type = data.get("entity_type") or None
        self.id = data.get("id") or None
        self.standard_id = data.get("standard_id") or None
        self.name = data.get("name") or None
        self.description = data.get("description") or None
        self.pattern_type = data.get("pattern_type") or None
        self.pattern = data.get("pattern") or None
        self.confidence = data.get("confidence")
        self.x_opencti_score = data.get("x_opencti_score")
        self.x_opencti_platforms = data.get("x_opencti_platforms") or []

        self.observables = (
            [Observable(observable) for observable in data["observables"]]
            if "observables" in data
            else []
        )


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
