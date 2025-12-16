# isort:skip_file
"""Offer fake api/v1/product endpoint router."""
import pathlib
import json
from typing import List, Optional

from fastapi import APIRouter, Path, Query, Response
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/products", tags=["Products"])

products_json_path = pathlib.Path(__file__).parent.resolve() / "data" / "products.json"


@router.get("/")
async def get_products(
    page: int = Query(1, description="Page number"),
    page_size: int = Query(50, description="Page size", le=500),
    sort_by: Optional[str] = Query("release_date", description="Sort by field"),
    sort_desc: bool = Query(False, description="Sort descending"),
    updated_after: Optional[str] = Query(None, description="Filter by update date"),
    released_after: Optional[str] = Query(None, description="Filter by release date"),
    serials: Optional[List[str]] = Query(  # noqa: B008
        None, description="Filter by serials"
    ),
    indicator: Optional[str] = Query(None, description="Filter by indicator"),
) -> JSONResponse:
    """Get products."""
    # load products from /data/products.json
    with open(products_json_path, "r", encoding="utf8") as f:
        products = json.load(f)

    # sort products
    products = sorted(products, key=lambda p: p[sort_by], reverse=sort_desc)

    # filter products
    if updated_after:
        products = [p for p in products if p["updated_at"] > updated_after]
    if released_after:
        products = [p for p in products if p["release_date"] > released_after]
    if serials:
        products = [p for p in products if p["serial"] in serials]
    if indicator:
        raise NotImplementedError("Filter by indicator is not implemented yet")

    # paginate products
    total = len(products)
    total_pages = (total + page_size - 1) // page_size
    products = products[(page - 1) * page_size : page * page_size]

    return JSONResponse(
        {
            "products": products,
            "total": total,
            "page_size": page_size,
            "total_pages": total_pages,
            "page": page,
        },
        status_code=200,
    )


@router.get("/{id}")
async def get_product(
    id: str = Path(..., description="Product serial number")
) -> JSONResponse:
    """Get product by serial number."""
    # load products from /data/products.json
    with open(products_json_path, "r", encoding="utf8") as f:
        products = json.load(f)
    product = next((p for p in products if p["serial"] == id), None)
    if not product:
        return JSONResponse({"message": "Product not found"}, status_code=404)
    return JSONResponse(product, status_code=200)


@router.get("/{id}/csv")
async def get_product_csv(
    id: str = Path(..., description="Product serial number")
) -> JSONResponse:
    """Get product csv."""
    raise NotImplementedError


@router.get("/{id}/stix2")
async def get_product_stix2(
    id: str = Path(..., description="Product serial number")
) -> JSONResponse:
    """Get product stix2."""
    raise NotImplementedError


@router.get("/{id}/report")
async def get_product_report(
    id: str = Path(..., description="Product serial number")
) -> Response:
    """Get product report."""
    # chek if serial is valid
    # load products from /data/products.json
    with open(products_json_path, "r", encoding="utf8") as f:
        products = json.load(f)
        product = next((p for p in products if p["serial"] == id), None)
    if not product:
        return Response(content="Product not found", status_code=404)
    # Create fake pdf content
    text = f"Fake PDF serial:{id}".encode("utf-8")
    text_length = len(text) + 20  # Adjust length based on content
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
        b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
        b"3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]/Contents 4 0 R>>\nendobj\n"
        b"4 0 obj\n<</Length "
        + str(text_length).encode()
        + b">>stream\nBT /F1 12 Tf 50 150 Td ("
        + text
        + b") Tj ET\nendstream\nendobj\n"
        b"5 0 obj\n<</Type/Font/Subtype/Type1/Name/F1/BaseFont/Helvetica>>\nendobj\n"
        b"xref\n0 6\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000100 00000 n \n"
        b"0000000200 00000 n \n0000000300 00000 n \ntrailer\n<</Size 6/Root 1 0 R>>\nstartxref\n400\n%%EOF"
    )
    return Response(content=pdf_content, media_type="application/pdf")
