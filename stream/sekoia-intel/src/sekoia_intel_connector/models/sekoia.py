class IOCImport:
    """
    Represent an IOC to import in Sekoia
    """

    def __init__(
        self,
        format: str | None = None,
        indicators: str | None = None,
        kill_chain_phases: list[dict] | None = None,
        valid_from: str | None = None,
        valid_until: str | None = None,
        description: str | None = None,
    ):
        self.format = format
        self.indicators = indicators
        self.kill_chain_phases = kill_chain_phases
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.description = description

    def to_dict(self) -> dict:
        """
        Convert the IOCImport instance into a JSON-serializable dict,
        """
        data = {
            "format": self.format,
            "indicators": self.indicators,
            "kill_chain_phases": self.kill_chain_phases,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "description": self.description,
        }
        # Remove the keys where the value is None
        return {k: v for k, v in data.items() if v is not None}
