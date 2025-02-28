# isort:skip_file
"""Offer fake server for the Dragos API V1 endpoints."""

from typing import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from client_api.dev.fake_server.v1.indicators import router as indicators_router
from client_api.dev.fake_server.v1.product import router as product_router


class V1AuthMiddleware(BaseHTTPMiddleware):
    """Define Middleware to authenticate requests to /api/v1/* endpoints."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response | JSONResponse:
        """Dispatch method for the middleware."""
        api_token = request.headers.get("API-Token")
        api_secret = request.headers.get("API-Secret")

        if api_token != "dev" or api_secret != "dev":  # noqa: S105
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        return await call_next(request)


v1_app = FastAPI()
v1_app.include_router(product_router)
v1_app.include_router(indicators_router)

app = FastAPI()
app.mount("/api/v1", v1_app)
app.add_middleware(V1AuthMiddleware)
