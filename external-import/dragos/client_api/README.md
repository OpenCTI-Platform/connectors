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


## Dev

A dev fake server Api is provided to test the client. It is a simple FastAPI server that simulates the Dragos API. It is used for testing the client.

To use it you need to install the project with the `dev`extra:

```bash
pip install -e .[dev]
```

### Data
The fake server uses a simple json file to store the data. The data should be stored in the `client_api/dev/fake_server/data` directory in `products.json`and `indicator.json` files.	

Lucky Filigran Developper can find a complete example on connector development Notion Page (under Usefull Resource section).

### Run

The fake server can be run with the following command:

```bash
cd client_api/dev/fake_server
python -m uvicorn main:app --port 4000 
```
Then you can find the Base URL in the terminal output (here http://127.0.0.1:4000).
```
INFO:     Started server process [15748]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:4000 (Press CTRL+C to quit)      
INFO:     127.0.0.1:65483 - "GET /api/v1/products/ HTTP/1.1" 200 OK
INFO:     127.0.0.1:49952 - "GET /api/v1/products/DOM-2024-08 HTTP/1.1" 200 OK
```

An interactive documentation is available at http://<base_url>/api/v1/docs

### Authentication

You must use a header with the values 

API-Token: dev
API-Secret: dev

Not providing this can be useful to test application reaction to a 401 error response.

### Results

see [docs](./dev/docs/)

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
