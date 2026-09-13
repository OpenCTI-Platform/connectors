import time
from datetime import date, datetime, timedelta, timezone

import requests
from trukno_connector.models import BreachSummary


class TruKnoClient:
    def __init__(self, base_url: str, api_key: str, session=None, sleep=None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = session or requests.Session()
        self._sleep = sleep or time.sleep

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._authorization_value(),
            "Accept": "application/json",
        }

    def _authorization_value(self) -> str:
        if self.api_key.casefold().startswith("bearer "):
            return self.api_key
        return f"Bearer {self.api_key}"

    def _get(
        self,
        url: str,
        params: dict | None = None,
        allow_empty_400: bool = False,
    ):
        for attempt in range(3):
            response = self.session.get(
                url,
                headers=self._headers(),
                params=params,
                timeout=60,
            )
            if getattr(response, "status_code", None) != 429 or attempt == 2:
                if allow_empty_400 and getattr(response, "status_code", None) == 400:
                    try:
                        if response.json() == []:
                            return None
                    except ValueError:
                        if getattr(response, "content", None) == b"":
                            return None
                response.raise_for_status()
                return response
            self._sleep(2**attempt)

        raise RuntimeError("Unreachable request retry state")

    def list_updated_breaches(
        self, updated_after: str, scan_after: str | None = None
    ) -> list[BreachSummary]:
        checkpoint = self._parse_timestamp(updated_after)
        items_by_id: dict[str, BreachSummary] = {}
        window_date = self._parse_timestamp(scan_after or updated_after).date()

        while window_date <= self._today():
            date_value = window_date.isoformat()
            next_date_value = (window_date + timedelta(days=1)).isoformat()
            for has_ttps in ("true", "false"):
                page = 1
                while True:
                    response = self._get(
                        f"{self.base_url}/breaches/list",
                        params={
                            "limit": 100,
                            "page": page,
                            "sortBy": "updatedate",
                            "start_date": date_value,
                            "end_date": next_date_value,
                            "hasTTPs": has_ttps,
                        },
                        allow_empty_400=has_ttps == "false",
                    )
                    if response is None:
                        break
                    payload = response.json()

                    for item in payload.get("results", []):
                        published_at = item["date"]
                        if self._parse_timestamp(published_at) <= checkpoint:
                            continue
                        summary = BreachSummary(id=item["_id"], updated_at=published_at)
                        existing = items_by_id.get(summary.id)
                        if existing is None or self._parse_timestamp(
                            summary.updated_at
                        ) > self._parse_timestamp(existing.updated_at):
                            items_by_id[summary.id] = summary

                    total_pages = int(
                        payload.get("metadata", {}).get("totalPages", 1) or 1
                    )
                    if page >= total_pages:
                        break
                    page += 1
            window_date += timedelta(days=1)

        return sorted(
            items_by_id.values(),
            key=lambda item: self._parse_timestamp(item.updated_at),
        )

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _today() -> date:
        return datetime.now(timezone.utc).date()

    def get_breach_details(self, breach_id: str) -> dict:
        return self._get(f"{self.base_url}/breaches/{breach_id}").json()
