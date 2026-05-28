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
            self.logger.error("Unexpected error.", {"error": str(err)})
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
