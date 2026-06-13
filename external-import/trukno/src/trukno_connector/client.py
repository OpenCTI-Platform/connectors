import requests
from trukno_connector.models import BreachSummary


class TruKnoClient:
    def __init__(self, base_url: str, api_key: str, session=None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = session or requests.Session()

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self.api_key}

    def list_updated_breaches(self, updated_after: str) -> list[BreachSummary]:
        response = self.session.get(
            f"{self.base_url}/breaches",
            headers=self._headers(),
            params={"updated_after": updated_after},
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()
        items = [
            BreachSummary(id=item["id"], updated_at=item["updatedAt"])
            for item in payload.get("items", [])
        ]
        return sorted(items, key=lambda item: item.updated_at)

    def get_breach_details(self, breach_id: str) -> dict:
        response = self.session.get(
            f"{self.base_url}/breaches/{breach_id}",
            headers=self._headers(),
            timeout=60,
        )
        response.raise_for_status()
        return response.json()
