class Indicator:
    """
    Represent an Indicator (SDO) from OpenCTI.
    Indicator's observables are from both OpenCTI API and parsed STIX pattern.
    All other fields returned by OpenCTI API are discarded.
    """

    def __init__(self, data, opencti_url: str | None = None):
        self.type = data.get("type") or None
        self.id = data.get("id") or None
        self.name = data.get("name") or None
        self.description = data.get("description") or None
        self.pattern_type = data.get("pattern_type") or None
        self.pattern = data.get("pattern") or None
        self.valid_from = data.get("valid_from") or None
        self.valid_until = data.get("valid_until") or None
        self.confidence = data.get("confidence") or None
        self.kill_chain_phases = data.get("kill_chain_phases") or None
        self.revoked = data.get("revoked") or False
        extensions = data.get("extensions") or None
        self.opencti_id = None
        self.opencti_url = None

        # If the indicator has extensions, we can extract the OpenCTI ID and URL
        if extensions and len(extensions) > 0:
            ext = next(iter(extensions.values()), None)
            if ext:
                self.opencti_id = ext.get("id") or None
                self.opencti_url = (
                    f"{opencti_url}/dashboard/observations/indicators/{self.opencti_id}"
                    if opencti_url
                    else None
                )
