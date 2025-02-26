# client_api Package

The `client_api` package provides tools and clients to interact with the Dragos Worldview API. It includes modules for handling common functionalities, errors, warnings, and specific API endpoints such as indicators and products.

## Reference

- Worldview V1 API documentation [consulted on 2025-02-26]: https://portal.dragos.com/api/v1/doc/index.html

## Quick start

To use the clients provided by this package, you need to initialize them with the appropriate parameters such as `base_url`, `token`, `secret`, `timeout`, `retry`, and `backoff`. The clients offer methods to make requests to the API and handle the responses.

Example:

```python
from datetime import datetime, timedelta, timezone
from yarl import URL
from pydantic import SecretStr

from client_api.v1 import DragosClientAPIV1
from client_api.error import DragosAPIError

client = DragosClientAPIV1(
    base_url=URL("https://portal.dragos.com"),
    token=SecretStr("ChangeMe"),
    secret=SecretStr("ChangeMe"),
    timeout=timedelta(seconds=10),
    retry=3,
    backoff=timedelta(seconds=5),
)
async def last_day():
    # Note: this assumes no errors are raised in the request in iter_indicators.
    async for indicator in client.indicator.iter_indicators(
        updated_after=datetime.now(timezone.utc) - timedelta(days=1)
    ):
        # Complex logic here
        pass

asyncio.run(last_day())
```

## Modules

### error
This module defines custom exceptions for handling errors related to the Dragos API.

### warning
This module provides custom warnings and tools for handling validation warnings in the API responses.

### v1
This subpackage contains modules for interacting with version 1 of the Dragos Worldview API. It includes clients and response models for specific API endpoints such as indicators and products.

#### indicator
This module provides the client and response models for the Dragos Worldview API indicator endpoint. It includes classes for handling indicator responses and making requests to the indicator API.

#### product
This module provides the client and response models for the Dragos Worldview API product endpoint. It includes classes for handling product responses and making requests to the product API.

