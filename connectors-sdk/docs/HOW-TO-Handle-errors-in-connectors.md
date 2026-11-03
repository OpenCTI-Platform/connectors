# How To handle errors in connectors

## Basic best practices

- **Keep `try/except` block as little as possible**

    → Helps with **error localization**, easier **unit testing**, and avoids **catching unintended side errors**.

- **Custom Exceptions, `raise from` in re-raising case**

    → Use custom exceptions for **clarity and control**; use `raise ... from ...` to **preserve the traceback** and maintain context.

    → Use `from None`  **intentionally**, to remove sensitive values.

- **Try/except the most specific error first**

    → Ensures that **known and expected exceptions** are handled properly, then the Exception groups.

- **Except with dedicated logging**

    → Logging exceptions helps with **debugging and monitoring**, especially in production environments. Avoid silent failures.

- **Unit test error raising**

    → Verifies that **expected failures** are raised properly.

- **Try to handle exceptions at the highest possible level (application layer)**

    → Encourages **centralized and consistent error handling**, allowing lower layers to stay focused on business logic.

- **Try to avoid sentinel values**

    → Sentinel values (like `None`, `-1`, or empty strings) can **mask errors** and make code harder to read or debug; prefer **exceptions** and eventually consider[`User/RuntimeWarning`](https://docs.python.org/3/library/exceptions.html#RuntimeWarning)

- **SystemExit / KeyboardInterrupt**

    → Should **not be caught casually**; they indicate a **user/system-initiated shutdown** and should be **allowed to propagate** to exit cleanly. Always catch them before any `except Exception` clause.

## Connector dedicated best practices

- **Do not interpret logs to aggregate them in a message**

    → Logs should be **structured and granular**; post-processing them to form messages makes parsing, monitoring, and debugging **less reliable and harder to automate**.

- **`ConfigError` ⇒ raised because it can be operated on**

    → Signals a **actionable problem** in configuration and allows the user to **respond appropriately immediately**. This error should be raised as soon as possible.

- **DataRetrieval/FetchError**

    → A potentially recoverable custom error that can be used to indicate that the connector is not responsible for the encountered error, but rather the data source is..

- **Normalize/Process/Conversion/UseCase Error**

    →A custom error indicating that the connector is not handling the process properly. This error can be recoverable or skipped in the application layer if it is designed to iterate over entities.

- **Logging levels (Decided with OCTI product teams)**
  - **DEBUG**: Open bar : log anything useful for **deep technical inspection**. We are far from performances issues due to logging, but we do spend huge amount of time debugging unexpected behavior.
  - **INFO**: Track **normal operational milestones** (e.g., "connector started", known quirks, or documented uncertainties).
  - **WARNING**: Used for **non-blocking errors** that are **handled and/or skipped** gracefully.
  - **ERROR**: Reserved for **unexpected, unhandled exceptions**, typically in a `except Exception:` block. This should be limited to the strict minimum.
- **`except` Exception in connector run**

    → Used to **prevent connector crash**, but should be **restricted** to top-level control flow and always followed by **logging and OCTI platform alerting**.

- **Use `finally` ⇒ cleanup vars** (e.g. `last_run`, `work_id`, `last_ingested`)

    → Ensures **essential finalization and state recording** happen even if an error occurs.

## Standardized connector errors

The SDK defines a shared set of errors so that every connector describes a failure the same way. Each error carries a standardized `code` and a `criticity`:

| Criticity | Value | Meaning |
|---|---|---|
| `Criticity.CRITICAL` | 50 | The run fails and will keep failing until someone intervenes |
| `Criticity.ERROR` | 40 | The run fails, but a later attempt may succeed |
| `Criticity.WARNING` | 30 | One item fails; the run skips it and continues |

The values are the matching `logging` levels.

All errors derive from `ConnectorError`, grouped into categories:

| Category | Error | Code | Criticity |
|---|---|---|---|
| `ConfigurationError` | `ConfigurationInvalidError` | `config.invalid` | CRITICAL |
| `ProviderApiError` (the source the connector reads) | `ProviderApiAuthenticationError` | `api.authentication` | CRITICAL |
| | `ProviderApiAuthorizationError` | `api.authorization` | CRITICAL |
| | `ProviderApiNotFoundError` | `api.not_found` | CRITICAL |
| | `ProviderApiRateLimitError` | `api.rate_limit` | ERROR |
| | `ProviderApiServerError` | `api.server` | ERROR |
| | `ProviderApiTimeoutError` | `api.timeout` | ERROR |
| | `ProviderApiConnectionError` | `api.connection` | ERROR |
| | `ProviderApiInvalidResponseError` | `api.invalid_response` | ERROR |
| | `ProviderApiUnknownError` | `api.unknown` | ERROR |
| `OctiError` | `OctiAuthenticationError` | `octi.authentication` | CRITICAL |
| | `OctiVersionIncompatibleError` | `octi.version_incompatible` | CRITICAL |
| | `OctiUnreachableError` | `octi.unreachable` | ERROR |
| `TargetError` (stream targets) | `TargetAuthenticationError` | `target.authentication` | CRITICAL |
| | `TargetAuthorizationError` | `target.authorization` | CRITICAL |
| | `TargetRateLimitError` | `target.rate_limit` | ERROR |
| | `TargetUnreachableError` | `target.unreachable` | ERROR |
| | `TargetRejectedError` | `target.rejected` | WARNING |
| `DataError` (one item) | `DataNotFoundError` | `data.not_found` | WARNING |
| | `DataConversionError` | `data.conversion` | WARNING |
| | `DataInvalidValueError` | `data.invalid_value` | WARNING |
| | `DataUnsupportedTypeError` | `data.unsupported_type` | WARNING |
| | `DataOutOfScopeError` | `data.out_of_scope` | WARNING |
| | `DataTlpExceededError` | `data.tlp_exceeded` | WARNING |
| | `DataMissingDataError` | `data.missing_data` | WARNING |
| none | `UnknownError` | `other.unknown` | CRITICAL |

- **Raise the concrete errors, catch the categories**

    → `ConnectorError` and the categories are abstract: instantiating them raises a `TypeError`. Use them only in `except` clauses to handle a whole family.

    ```python
    from connectors_sdk import DataError, DataConversionError, ProviderApiError

    for item in items:
        try:
            stix_objects.extend(converter.convert(item))
        except DataError as err:  # one item fails: log it, skip it, keep going
            logger.warning("Skipping item", {"code": err.code, "error": str(err)})


    def convert(item):
        try:
            ...
        except KeyError as err:
            raise DataConversionError(f"Missing field in {item['id']}") from err
    ```

- **Specialize a standard error rather than inventing a code**

    → A subclass of a concrete error keeps its code and criticity (`class MyFeedTimeoutError(ProviderApiTimeoutError): ...`). A new concrete subclass of a category must declare both `code` and `criticity`, or the class definition raises a `TypeError`.

- **`BaseClientApi` still raises the older errors for now**

    → `BaseClientApi` raises `ApiClientError` and its subclasses (`ApiNotFoundError`, …), which are not `ConnectorError`s yet. The same goes for `ConfigError`, `DataRetrievalError` and `UseCaseError`. Catch them and re-raise the matching standardized error when needed.

### Reporting errors to OpenCTI

`ErrorStore()` always returns the same store, so any part of the connector can record a handled error without passing an object around. At the end of a scheduled run, return the recorded errors from the callback given to `helper.schedule_process`: pycti sends them to OpenCTI with the connector's ping.

```python
from connectors_sdk import DataConversionError, ErrorStore


def process_message(self):
    store = ErrorStore()
    store.clear()  # a run starts with an empty store
    for item in items:
        try:
            ...
        except DataConversionError as err:
            store.record_error(err)  # handled: the run skips the item and continues
    return [error.convert_to_pycti_format() for error in store.get_errors()]
```

- `record_error` accepts `ConnectorError` instances only: convert an older SDK error into its standardized counterpart before recording it.
- `get_errors` returns the recorded error objects, in order. `convert_to_pycti_format()` turns each one into the `{"code", "message", "criticity"}` dict pycti expects.
- **Clear the store at the start of each run**: otherwise the errors of previous runs are reported again. The SDK base classes (`ExternalImportConnector`) don't do it for you yet.
- pycti keeps **one error per code** (the last one recorded wins) and **20 errors at most**, the most critical first.
- The store is shared by the threads of a process, not across processes.

### Skipping a failed item with `swallow_connector_errors`

`@swallow_connector_errors(default=...)` replaces the `try / except ConnectorError / record_error / return a fallback` block. When the decorated function raises a `ConnectorError`, the decorator records it in `ErrorStore` and returns `default` instead. Decorate the function called for **one item**, with `default=[]`, and iterate over its result with `yield from`: a failed item yields nothing and the loop goes on with the next one.

```python
from collections.abc import Iterator

from connectors_sdk import DataConversionError, swallow_connector_errors


class Converter:
    @swallow_connector_errors(default=[])
    def convert(self, item: dict) -> list[Stix]:
        if "id" not in item:
            raise DataConversionError("Missing id")
        return [...]

    def convert_all(self, items: list[dict]) -> Iterator[Stix]:
        for item in items:
            yield from self.convert(item)  # a failed item yields nothing
```

- **Use it with parentheses**: `@swallow_connector_errors()` returns `None` on error, `@swallow_connector_errors(default=[])` returns an empty list. `@swallow_connector_errors` alone raises a `TypeError`. Type checkers see the fallback: with `default=None`, a function returning `list[Stix]` becomes `list[Stix] | None`.
- **Never decorate a generator**: the code of a generator, an async generator or a coroutine runs after the decorator returns, so the decorator could not catch its errors, and a generator can't be resumed once an exception has left it. Decorating one of these functions raises a `TypeError` on import, and a decorated function that returns an iterator (a generator expression, `map`, `filter`, `iter(...)`) raises a `TypeError` on call. Return a list, or decorate the per-item function as above.
- **Each swallowed call returns a shallow copy of `default`**: a `[]` or `{}` default is never shared between calls. A default holding mutable objects shares them.
- **Every `ConnectorError` is swallowed, whatever its criticity**: a `ProviderApiAuthenticationError` (bad API key) is swallowed too, and then repeats for every item. Decorate only the functions whose failures concern one item, and let the errors that stop the run be raised elsewhere. Exceptions that aren't `ConnectorError`s (`ValueError`, `KeyboardInterrupt`, the older `ApiClientError`s…) propagate unchanged.
- **Swallowed errors aren't logged yet**: they are only recorded in `ErrorStore` and reach OpenCTI with the ping. Log them yourself if you need them in the connector's logs.

## Example

Non working example of error handling in a connector:

```python
# README.md
...
The endpoint to recover pdf is not documented and not supported by the data source team.
This could be absent from the retrieved data.
...  

# client_api.py
...
class IOCResponseModel(PermissiveBaseModel):
    ...
    id: str
    value: str
    type: PermissiveLiteral[Literal["domain", "ip", "hash"]]  # emit warning if not in list
    description: Optional[str] = None  # Optional, eventually unused
    created_at: Recommended[str] = None  # optional, but will emit a warning if 
    # if other values are present a warning will be emitted

...
class ClientAPI:
    ...
    def get_ioc(self, ioc_id: str)-> IOCResponseModel:
        ...
        try: 
            response = self.get(endpoint=self.base_url/"iocs"/ioc_id)
            response.raise_for_status()
            json_data = response.json()
            return IOCResponseModel(**json_data)

        except (HTTPError, ReadTimeoutError, ValidationError) as err:
            ...
            logger.debug(
                "error fetching iocs", 
                {
                    "url": self.base_url/"iocs", 
                    "params": params, 
                    "header_without_creds": ...
                }
            )
            # Transform to known exception for later
            raise DataRetrievalError(
                f"The data source was not able to provide the required data for ioc {ioc_id}"
                ) from err
    ...
    def get_pdf(self, pdf_id: str) -> Optional[bytes]:
        ...
        try: 
            response = self.get(endpoint=self.base_url/"pdf"/pdf_id)
        except (requests.HTTPError, aiohttp.ReadTimeoutError) as err:
            ...
            # Documented behavior see README.md => INFO
            logger.info(
                f"PDF {pdf_id} cannot be retrieved"
                )
            logger.debug(
                "PDF retrieval failed", exc_info=err
                )
            response = None        
...

# config.py
...
   class OpenCTIConfig(pydantic.BaseModel)
       ...
       def __init__(self, **kwargs):
           ...
           try:
               pydantic.BaseModel.__init__(self, model_values)
           # Transform to known exception for later
           except pydantic.ValidationError as err:
               logger.debug(...)
               raise ConfigError(msg) from err
...

# converter.py
...
    def convert_ioc(self, ioc:IOCResponseModel, raw_pdf=None)->list[Entities]:
        ...
        match ioc_type:
            case "domain":
                ...
                return DomainName(**params)
            ...
            case _:
                # Transform to known exception for later
                raise UseCaseError(
                    f"Unsupported ioc type {ioc_type}"
                        )
# connector.py
...
    def etl(self, _id: str) -> None:
        ...
        try:
                ioc = self.client.get_ioc(_id)
                pdf = self.client.get_pdf(_id)
                processed_entities = self.converter.convert_ioc(ioc, pdf)
                self.send(processed_entities)
        except (DataRetrivalError, UseCaseError) as err:
            # SKIPPING WITH JUST A LOG WARNING
        logger.warning(
                "Cannot processed id {_id}. It is skipped",
                exc_info=err
            )
        
    def work(self)-> None:
        mark_in_error_flag = False      
        try: 
            ids = self.client.get_ids(start_date, end_date)
            logger.debug(f"Found {len(ids)} to process")
            for _id in ids:
                self.etl(_id)
        except DataRetrievalError as err:  # get_ids failed
            logger.warning("Failed to reach data source", exc_info=err)
        except (KeyboardInterrupt, SystemExit):
            # for instance, allow Ctrl+C to stop  and  
            # display error message in the OpenCTI UI
            # THE CONNECTOR WILL NOT RUN AGAIN     
            self.helper.api.work.report_expectation(
                work_id=self.work_id, error=
                {"error": "Connector stopped by user/system", "source": "CONNECTOR"}
                )   
            mark_in_error_flag = True      
            sys.exit(0)
        except Exception as err: 
            # Log error in Error Handler
            self.logger.error("Unexpected error.", meta={"error": str(err)})
            # display error message in the OpenCTI UI            
            self.helper.api.work.report_expectation(
                work_id=self.work_id, error={"error": error_message, "source": "CONNECTOR"}
                )
            mark_in_error_flag = True 
        finally:
            self.helper.api.work.to_processed(
                work_id=self.work_id,
                message="Connector's work finished gracefully",
                in_error=mark_in_error_flag,
                )
            # Clean up vars
            self.work_id = None
            self.data_in_connector_state=None
...
        
# main.py

if __name__ == "__main__":
    import traceback
    ... 
    # Configuration    
    try:        
        config = ConfigLoader()
        client = ClientAPI(...)
        connector = Connector(
                config = config,
                client = client, 
                ...
                )
        ...
    except Exception as err:
        # ONLY start up issue exceptions, otherwise shoud be handle gracefully by the connector        
        traceback.print_exc()        
        sys.exit(1)
    
    connector.run()   
    

# test_client.py

def test_get_ioc_should_raise_data_retrieval_error():
    # Given a client with _get method raising HTTPERROR with 401 code
    ...
    client._get = Mock()
    client._get.side_effect = HTTPError(response=Mock(status_code=401))
    # When calling get_ioc method
    # Then a DataRetrievalError is raised
    with pytest.raises(DataRetrievalError):
        client.get_ioc("dummy_id")
```
