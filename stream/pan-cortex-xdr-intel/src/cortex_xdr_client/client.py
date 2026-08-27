from pydantic import HttpUrl


class CortexXdrClient:
    """
    Client for the Palo Alto Cortex XDR "Insert or update IOCs" and "Delete
    Indicators/IOCs" APIs.
    """

    def __init__(self, api_base_url: HttpUrl, api_key_id: str, api_key: str) -> None:
        self.api_base_url = api_base_url
        self.api_key_id = api_key_id
        self.api_key = api_key

    def upsert_iocs(self, iocs: list[dict]) -> dict:
        raise NotImplementedError

    def delete_iocs(self, iocs: list[dict]) -> dict:
        raise NotImplementedError
