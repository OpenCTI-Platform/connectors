import time
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from flareio import FlareApiClient  # pylint: disable=import-error
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class FlareClient:  # pylint: disable=too-few-public-methods
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        api_key: str,
        base_url: HttpUrl,
        tenant_id: int | None,
    ) -> None:
        self.helper = helper
        self._api = FlareApiClient(
            api_key=api_key,
            api_domain=str(base_url),
            tenant_id=tenant_id,
        )

    def get_events(
        self,
        from_date: datetime,
        event_types: list[str],
        event_actions: list[str] | None,
    ) -> Iterator[dict[str, Any]]:
        last_from = None
        page_count = 0

        filters: dict[str, Any] = {}
        if event_types:
            filters["type"] = event_types

        filters["imported_after"] = from_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        for response in self._api.scroll(
            method="POST",
            url="/firework/v4/events/tenant/_search",
            json={"from": last_from, "filters": filters if filters else None},
        ):
            time.sleep(0.25)

            data = response.json()
            items = data.get("items", [])
            page_count += 1

            self.helper.connector_logger.debug(
                "Fetched page",
                {"page": page_count, "items_count": len(items), "cursor": last_from},
            )

            last_from = data.get("next")

            for item in items:
                uid = item.get("metadata", {}).get("uid")
                number_of_retries = 3
                for current_try in range(number_of_retries):
                    self.helper.connector_logger.debug(
                        "Fetching event",
                        {
                            "uid": uid,
                            "attempt": current_try + 1,
                            "max_attempts": number_of_retries,
                        },
                    )
                    try:
                        event_response = self._api.get(
                            url=f"/firework/v2/activities/{uid}"
                        )
                        event_response.raise_for_status()

                        event_json = event_response.json()
                        event_data = event_json.get("activity")
                        event_data["tenant_metadata"] = item.get("tenant_metadata")

                        header = event_data.get("header", {})
                        is_remediated = header.get("remediated_at") is not None
                        is_ignored = header.get("ignored_at") is not None

                        if event_actions:
                            known_actions = {"ignored", "remediated"}
                            configured_actions = set(event_actions)
                            if (
                                len(configured_actions) > 0
                                and not configured_actions & known_actions
                            ):
                                self.helper.connector_logger.info(
                                    "Unsupported event actions configured — only 'ignored' and 'remediated' are supported",
                                    {"configured_actions": list(configured_actions)},
                                )
                            elif "ignored" in event_actions and not is_ignored:
                                self.helper.connector_logger.debug(
                                    "Skipping event — not ignored",
                                    {"uid": uid},
                                )
                                break
                            elif "remediated" in event_actions and not is_remediated:
                                self.helper.connector_logger.debug(
                                    "Skipping event — not remediated",
                                    {"uid": uid},
                                )
                                break

                        yield event_data
                        break
                    except Exception as e:
                        self.helper.connector_logger.error(
                            "Failed to fetch event",
                            {
                                "uid": uid,
                                "attempt": current_try + 1,
                                "max_attempts": number_of_retries,
                                "error": str(e),
                            },
                        )
                        time.sleep(1)
