# api_engine

## TL;DR

- **Resilient async HTTP engine wrapping aiohttp.** Three composable reliability layers: retry with exponential backoff, circuit breaker, and sliding-window rate limiter.
- **Typed error boundary.** Every failure surfaces as an `ApiError` subclass. No raw Python exceptions leak out.
- **Fully interface-driven.** Six ABCs in `interfaces/` let you swap transport, circuit breaker, rate limiter, or hooks without touching call sites.
- **Rate limiting is process-global by key.** `RateLimiterRegistry` deduplicates limiters so multiple strategy instances targeting the same upstream share one bucket.
- **Hooks for auth and observability.** `BaseRequestHook.before()` / `.after()` run on every request, ideal for token injection or logging.
- **Pydantic-validated responses.** Pass `response_model` and the engine validates + coerces the JSON response for you.

---

## Overview

`api_engine` is a resilient async HTTP client engine. It wraps `aiohttp` behind a typed interface stack and adds three reliability layers: retry with exponential backoff, a circuit breaker, and a sliding-window rate limiter. These compose independently.

All error conditions produce typed `ApiError` subclasses. No raw Python exceptions (`KeyError`, `ValueError`, etc.) escape through the package boundary.

---

## Architecture

```
ApiClient                           ← thin public facade
  └── RetryRequestStrategy          ← retry + circuit breaker + rate limiter + hooks
        ├── AioHttpClient           ← aiohttp transport, error classification
        ├── CircuitBreaker          ← open/close state, instance-level counters
        ├── TokenBucketRateLimiter  ← sliding-window token bucket, async lock
        └── BaseRequestHook[]       ← pre/post request extension points

ApiRequestModel                     ← Pydantic request descriptor (URL, method, headers…)
RateLimiterRegistry                 ← process-wide singleton store keyed by string
exceptions/                         ← ApiError hierarchy (7 classes)
interfaces/                         ← 6 ABCs for custom implementations
```

**`AioHttpClient`** is the concrete `BaseHttpClient`, backed by a shared `aiohttp.ClientSession` (lazy-initialized on first call, closed explicitly via `close()`). It classifies aiohttp and asyncio exceptions into `ApiTimeoutError`, `ApiNetworkError`, `ApiRateLimitError` (HTTP 429), and `ApiHttpError` (all other 4xx/5xx).

**`CircuitBreaker`** counts consecutive failures per instance. Once `max_failures` is reached the circuit opens; it auto-resets after `cooldown_time` seconds. State is instance-level: two `CircuitBreaker` objects never share counters. Call `reset()` explicitly to close the circuit on a successful path from outside the strategy.

**`RetryRequestStrategy`** is the orchestration core. It checks the circuit, acquires a rate-limiter slot, runs `before` hooks, dispatches to the HTTP client, runs `after` hooks, then parses the response. Retryable failures (timeouts, rate limits, 5xx, 429) sleep for `backoff × attempt_number` seconds before the next attempt. Non-retryable 4xx (everything except 429) raises immediately. Exhausted retries surface the last exception and log at ERROR.

**`TokenBucketRateLimiter`** is a sliding-window bucket backed by a timestamp `deque`. `acquire()` blocks under an `asyncio.Lock` until a slot is available, logging at DEBUG when it waits.

**`RateLimiterRegistry`** is a class-level store that returns the same `TokenBucketRateLimiter` for a given string key. It prevents multiple strategy instances from creating competing limiters for the same upstream. Call `RateLimiterRegistry.clear()` in test fixtures to reset state between scenarios.

**`ApiRequestModel`** is the Pydantic model capturing all request parameters: `url`, `method`, `headers`, `params`, `data`, `json_body`, `response_key` (optional sub-field extraction), `response_model` (optional Pydantic model for response parsing), and `timeout`.

---

## Quick start

```python
import asyncio
from google_secops_siem_incidents.utils.api_engine import (
    AioHttpClient,
    ApiClient,
    CircuitBreaker,
    RetryRequestStrategy,
)


async def main() -> None:
    http = AioHttpClient(default_timeout=30)
    breaker = CircuitBreaker(max_failures=5, cooldown_time=60.0)
    strategy = RetryRequestStrategy(
        http_client=http,
        circuit_breaker=breaker,
        max_retries=3,   # 3 total attempts
        backoff=2.0,     # seconds × attempt number
    )
    client = ApiClient(strategy=strategy)

    try:
        result = await client.call_api("https://api.example.com/v1/events")
        print(result)
    finally:
        await http.close()


asyncio.run(main())
```

`call_api` returns the full parsed JSON dict by default. Pass `response_key` to extract a sub-field:

```python
items = await client.call_api(
    "https://api.example.com/v1/events",
    response_key="events",   # raises ApiValidationError if key is absent
)
```

Pass `response_model` to validate and coerce the response (or the extracted sub-field) into a Pydantic model:

```python
from pydantic import BaseModel

class Event(BaseModel):
    id: str
    severity: str

event = await client.call_api(
    "https://api.example.com/v1/events/abc123",
    response_model=Event,
)
```

---

## With rate limiting

Pass a config dict to `RetryRequestStrategy`. The registry ensures a single limiter instance per key across the process lifetime.

```python
strategy = RetryRequestStrategy(
    http_client=http,
    circuit_breaker=breaker,
    rate_limiter={
        "key": "secops-api",   # unique identifier for this upstream
        "max_requests": 10,    # max calls per…
        "period": 1.0,         # …this many seconds (sliding window)
    },
)
```

To share an explicit limiter instance directly, pass a `TokenBucketRateLimiter` object instead of a dict:

```python
from google_secops_siem_incidents.utils.api_engine import TokenBucketRateLimiter

limiter = TokenBucketRateLimiter(max_requests=10, period=1.0)
strategy = RetryRequestStrategy(
    http_client=http,
    circuit_breaker=breaker,
    rate_limiter=limiter,
)
```

---

## With request hooks

Implement `BaseRequestHook` to inject headers, log requests, or inspect responses.

```python
from typing import Any
from google_secops_siem_incidents.utils.api_engine import BaseRequestHook, BaseRequestModel


class BearerAuthHook(BaseRequestHook):
    def __init__(self, token: str) -> None:
        self._token = token

    async def before(self, request: BaseRequestModel) -> None:
        if request.headers is None:
            request.headers = {}
        request.headers["Authorization"] = f"Bearer {self._token}"

    async def after(self, request: BaseRequestModel, response: Any) -> None:
        pass  # no-op; inspect response here if needed


strategy = RetryRequestStrategy(
    http_client=http,
    circuit_breaker=breaker,
    hooks=[BearerAuthHook(token="my-token")],
)
```

Multiple hooks run in list order. `before` fires after rate limiting, before the HTTP call. `after` fires after a successful response, before response parsing.

---

## Error handling

All exceptions inherit from `ApiError`. Callers handle the `ApiError` family only: no raw Python exceptions escape `api_engine`.

| Exception | When raised |
|---|---|
| `ApiError` | Base class. Never raised directly. |
| `ApiHttpError` | HTTP status ≥ 400 (except 429). Carries `.status_code`. Not retried for 4xx ≠ 429. |
| `ApiRateLimitError` | HTTP 429 response. Retried by `RetryRequestStrategy`. |
| `ApiTimeoutError` | `asyncio.TimeoutError` or `aiohttp.ServerTimeoutError`. Retried. |
| `ApiNetworkError` | Connection/DNS/reset failures classified by `AioHttpClient`. Retried. |
| `ApiCircuitOpenError` | Circuit breaker is open. Not retried; raises immediately. |
| `ApiValidationError` | `response_key` absent from response dict, or Pydantic model validation failure. Not retried. |

`ApiHttpError` constructor: `ApiHttpError(message: str, status_code: int)`. The message is the first positional argument; `status_code` is keyword-preferred at call sites (see TDR-008).

Catching pattern:

```python
from google_secops_siem_incidents.utils.api_engine import (
    ApiCircuitOpenError,
    ApiError,
    ApiHttpError,
    ApiValidationError,
)

try:
    result = await client.call_api(url)
except ApiCircuitOpenError:
    # upstream is unhealthy; back off at a higher level
    ...
except ApiValidationError as exc:
    # response shape mismatch; log and skip
    ...
except ApiHttpError as exc:
    # check exc.status_code for 401, 403, 404, etc.
    ...
except ApiError:
    # catch-all for timeout / network / rate-limit exhaustion
    ...
```

---

## Extending

Every component is backed by an ABC in `interfaces/`. To replace the HTTP transport, subclass `BaseHttpClient` and implement `request()`; inject it as `http_client` in `RetryRequestStrategy`. To replace the circuit breaker, subclass `BaseCircuitBreaker` and implement `is_open()`, `record_failure()`, and `reset()`.

The strategy, rate limiter, hooks, and request model follow the same pattern: implement the interface, inject at construction time. `ApiClient` accepts any `BaseRequestStrategy`, so the entire execution pipeline swaps without changing call sites.

---
