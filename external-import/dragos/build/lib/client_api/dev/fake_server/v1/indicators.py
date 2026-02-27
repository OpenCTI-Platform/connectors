# isort:skip
"""Offer fake api/v1/indicators endpoint router."""

import json
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/indicators", tags=["Indicators"])

indicators_json_path = Path(__file__).parent.resolve() / "data" / "indicators.json"


@router.get("/")
async def get_indicators(
    exclude_suspect_domain: bool = Query(
        False,
        description="Exclude indicators that are only associated with Suspect Domain Reports",
    ),
    page: int = Query(1, description="Page number"),
    page_size: int = Query(500, description="Page size", le=1000),
    updated_after: Optional[str] = Query(None, description="Filter by update date"),
    value: Optional[str] = Query(None, description="Filter by value"),
    type: Optional[str] = Query(None, description="Filter by type"),
    serial: Optional[List[str]] = Query(  # noqa: B008
        None, description="Filter by serials"
    ),
    tags: Optional[List[str]] = Query(None, description="Filter by tags"),  # noqa: B008
) -> JSONResponse:
    """Get indicators."""
    # load indicators from /data/indicators.json
    with open(indicators_json_path, "r", encoding="utf8") as f:
        indicators = json.load(f)

    # filter indicators
    if exclude_suspect_domain:
        indicators = [i for i in indicators if not i.get("suspect_domain")]
    if updated_after:
        indicators = [i for i in indicators if i["updated_at"] > updated_after]
    if value:
        indicators = [i for i in indicators if value in i["value"]]
    if type:
        indicators = [i for i in indicators if i["type"] == type]
    if serial:
        filtered_indicators = []
        for indicator in indicators:
            for product in indicator.get("products", []):
                if product["serial"] in serial:
                    filtered_indicators.append(indicator)
                    break
        indicators = filtered_indicators

    if tags:
        indicators = [i for i in indicators if any(tag in i["tags"] for tag in tags)]

    # paginate indicators
    total = len(indicators)
    total_pages = (total + page_size - 1) // page_size
    indicators = indicators[(page - 1) * page_size : page * page_size]

    return JSONResponse(
        {
            "indicators": indicators,
            "total": total,
            "page_size": page_size,
            "total_pages": total_pages,
            "page": page,
        },
        status_code=200,
    )


@router.get(".stix2")
async def get_indicators_dot_stix2() -> JSONResponse:
    """Get indicators stix2."""
    raise NotImplementedError


@router.get("/stix2")
async def get_indicators_stix2() -> JSONResponse:
    """Get indicators stix2."""
    raise NotImplementedError
