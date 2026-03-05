import requests
from pycti import OpenCTIConnectorHelper

from .settings import ConnectorSettings


class PromptIntelClient:
    """API client for the PromptIntel platform."""

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.api_url = config.promptintel.api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {config.promptintel.api_key}",
                "Accept": "application/json",
            }
        )

    def health_check(self) -> dict:
        """Check API health status (no auth required)."""
        response = self.session.get(f"{self.api_url}/health")
        response.raise_for_status()
        return response.json()

    def get_prompts(
        self,
        page: int = 1,
        limit: int = 100,
        severity: str | None = None,
        category: str | None = None,
    ) -> dict:
        """Retrieve approved prompts with optional filtering and pagination."""
        params = {"page": page, "limit": limit}
        if severity:
            params["severity"] = severity
        if category:
            params["category"] = category
        response = self.session.get(f"{self.api_url}/prompts", params=params)
        response.raise_for_status()
        return response.json()

    def get_prompts_batch(
        self,
        max_items: int,
        severity: str | None = None,
        category: str | None = None,
        known_ids: set[str] | None = None,
    ) -> list[dict]:
        """Fetch prompts in pages up to *max_items*, stopping early when
        a page contains only already-known IDs (the API returns most-recent
        first, so hitting known IDs means we have caught up)."""
        all_prompts: list[dict] = []
        page = 1
        page_size = min(100, max_items)
        while len(all_prompts) < max_items:
            self.helper.connector_logger.info(
                "[PROMPTINTEL] Fetching prompts page",
                {"page": page, "collected": len(all_prompts), "target": max_items},
            )
            data = self.get_prompts(
                page=page, limit=page_size, severity=severity, category=category
            )
            prompts = data.get("data", [])
            if not prompts:
                break

            new_on_page = 0
            for p in prompts:
                if len(all_prompts) >= max_items:
                    break
                if known_ids and p.get("id") in known_ids:
                    continue
                all_prompts.append(p)
                new_on_page += 1

            if new_on_page == 0:
                self.helper.connector_logger.info(
                    "[PROMPTINTEL] No new prompts on page, stopping pagination.",
                    {"page": page},
                )
                break

            pagination = data.get("pagination", {})
            if page >= pagination.get("pages", 1):
                break
            page += 1
        return all_prompts

    def get_taxonomy(self) -> dict:
        """Retrieve the LLM Security Threats Classification taxonomy."""
        response = self.session.get(f"{self.api_url}/taxonomy")
        response.raise_for_status()
        return response.json()
