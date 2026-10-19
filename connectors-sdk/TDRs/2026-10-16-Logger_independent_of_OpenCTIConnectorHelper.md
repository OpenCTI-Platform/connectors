# TDR: Logger independent of `OpenCTIConnectorHelper`

<br>

## Overview

The `connectors_sdk.logger` module gives connectors a logger that does not need an `OpenCTIConnectorHelper`.
Its records have the same format as pycti's records.
It sets itself up when the first record is logged, so it works without any other SDK module.
Once the settings are parsed, their log level and format apply.
Like for pycti, `OPENCTI_JSON_LOGGING` decides who owns the logging setup: the SDK, or the developer.

```python
from connectors_sdk.logger import get_logger

logger = get_logger(__name__)
logger.info("Fetched indicators", meta={"count": 42})
```

<br>

## Motivation

`pycti` logs through its `AppLogger`, available as `pycti.OpenCTIConnectorHelper.connector_logger`. This has several drawbacks:

1. **Nothing can log before the helper exists.** Settings validation, client setup and startup errors happen before that. Plus, `pycti.OpenCTIConnectorHelper` connects to OpenCTI, which is not necessary for logging. 
2. **Every class that logs needs the helper.** An API client or a converter must receive the helper, only to log.
3. **Tests need a helper.** To check logs, a test must create or mock a helper.
4. **The API is not the standard one.** `AppLogger.info(message, meta)` does not accept the standard arguments, such as `exc_info`, `stacklevel` or `%` formatting.

Each SDK module must work alone: importing and using one module must not require another SDK module.
For example, a connector can use `connectors_sdk.states` without `connectors_sdk.settings`.
So the logger module must not depend on any other SDK module.

<br>

## Proposed Solution

### `get_logger()` and `ConnectorLoggerAdapter`

`get_logger(name)` returns a `ConnectorLoggerAdapter`.
It is a standard `logging.LoggerAdapter` around `logging.getLogger(name)`, with one more keyword argument: `meta`.

- `meta` goes into the `attributes` field of the record, like with pycti's `AppLogger`. So the JSON output is the same.
- The other arguments work as with a standard logger (`exc_info`, `stacklevel`, `%` formatting).
- In an `except` block, `exception()` logs the traceback, like with a standard logger. `error()` never adds it. pycti's `AppLogger.error()` always adds it, which gives empty `NoneType: None` tracebacks outside an `except` block.

### Who owns the logging setup

`OPENCTI_JSON_LOGGING` is an "all or nothing" switch, with the same meaning as for pycti:

| `OPENCTI_JSON_LOGGING` | Who owns the logging setup | What the SDK does |
|---|---|---|
| Enabled (default) | The SDK | It replaces every root handler with its own: records are written to stderr as JSON, with pycti's formatter. It sets the level. |
| Disabled | The developer | Once the settings are parsed, it calls `logging.basicConfig(level=...)`, like pycti: if nothing configured logging, it adds Python's default handler (plain text on stderr) and sets the level. Otherwise, it changes nothing: neither the handlers nor the level. |

`OPENCTI_JSON_LOGGING` accepts the same values as a pydantic `bool`. For example, `false`, `no`, `off` and `0` disable JSON, in any case.

### When the SDK sets up logging

Importing the SDK does not change the logging setup.
The SDK sets up logging at two moments, with the rules above:

1. **When the first record is logged, if JSON logging is enabled.** The SDK only reads the environment variables:
   - `OPENCTI_JSON_LOGGING`, to know whether JSON logging is enabled;
   - `CONNECTOR_LOG_LEVEL` for the level. When it is missing or invalid, the level is `error` until the settings are parsed, and a warning record says so.

   With JSON logging disabled, the developer owns the logging setup, so nothing happens at this moment.
2. **When the settings are parsed.** A settings parser calls `configure_logging(log_level, json_logging)` as soon as it knows the configuration (environment variables, `config.yml` or `.env`). pycti does the same: it sets up logging when it reads the configuration.
   `BaseConnectorSettings` calls it after validation, with `connector.log_level` and `opencti.json_logging`.
   `opencti.json_logging` is hidden from the connector's config schema (`SkipJsonSchema`), so that XTM Composer does not offer it when it deploys a connector. It can still be set with `OPENCTI_JSON_LOGGING`, `config.yml` or `.env`.

If the settings disable JSON logging while the environment variables did not (e.g. in `config.yml`), the SDK first removes the JSON handler it added at step 1.

If the settings were parsed before the first record, step 2 already happened, and the first record changes nothing.

### Class loggers

The SDK classes that log (connector, data processor, work manager, settings, states, API client) get a `logger` class attribute from `_ClassLoggerMixin`.
This logger is named after the module that defines the class.
So a connector's subclass logs under the connector's module name, and the SDK class logs under the SDK's module name.

A class must not define `logger` in its body: this raises a `TypeError`. This way, every class logs the same way.
Most tests check logs with `caplog` and do not need this. For testing purposes only, a test can replace the logger after the class is defined: `MyProcessor.logger = fake_logger`.

### How a connector keeps control

Most connectors should not configure logging themselves: the SDK setup gives the format OpenCTI expects.
If a connector really needs its own setup, it disables `OPENCTI_JSON_LOGGING`, then configures logging, for example with `logging.basicConfig()`.

With JSON logging enabled, a connector can still add handlers (a file, OpenTelemetry...) after the settings are parsed. The SDK does not remove them, unless `configure_logging()` is called again.
But `OpenCTIConnectorHelper` removes them when it is created, like any other root handler.

### Tests

pytest captures the records with its own handlers on the root logger. With JSON logging enabled, the SDK would replace them, and `caplog` would stop capturing records.
So tests disable JSON logging, for example in `conftest.py`:

```python
os.environ["OPENCTI_JSON_LOGGING"] = "false"
```

<br>

## Advantages

- **Log anywhere, at any time.** No helper is needed, even before it exists.
- **The configured level and format apply as soon as they are known.** This includes `config.yml` and `.env`, in production too.
- **Simple to test.** Records are standard `logging` records, so `caplog` works.
- **Same output as pycti.** Same JSON format, same `attributes` field.
- **Works alone.** It needs no other SDK module.
- **One clear switch.** `OPENCTI_JSON_LOGGING` decides who owns the logging setup, with the same meaning as for pycti.

<br>

## Disadvantages

- **The SDK changes the global logging configuration.** With JSON logging enabled (the default), it replaces every root handler. Python's guidelines recommend that libraries do not configure logging. The SDK does it anyway, like pycti, so that a connector works without any setup.
- **Tests must disable JSON logging.** Otherwise, `caplog` stops capturing records.
- **Some pycti values are copied.** The record format is not exposed by pycti. If pycti changes it, the SDK must follow.
- **`ConnectorLoggerAdapter` is not a `logging.Logger`.** Type hints must use `ConnectorLoggerAdapter`.

<br>

## Alternatives Considered

### Keep pycti's `AppLogger`, or a wrapper like `ConnectorLogger`

Rejected, for the reasons given in Motivation:

- Nothing can log before the helper exists.
- Every class that logs needs the helper.
- The API is not the standard one: no `exc_info`, no `stacklevel`, no `%` formatting.

### Set up logging when the SDK is imported

Rejected:

- Importing a library must not change the process.
- It would affect connectors that only use `connectors_sdk.models`, and never log through the SDK.
- A connector's own `logging.basicConfig()`, called later, would be ignored, because the root logger would already have a handler.
- The warning about a missing `CONNECTOR_LOG_LEVEL` made a test run with `-W error` fail at import time.

### An explicit setup function, called in `main.py`

For example, a context manager that sets up logging, validates the settings and handles errors.

Rejected:

- Logging would depend on the settings, so the logger could not be used alone.
- Every connector would have to call it, and could forget it.
- It adds one more concept to `main.py`, which non-developer contributors read first.

### Set up logging only when nothing else did, whatever `OPENCTI_JSON_LOGGING` says

Rejected: the meaning of `OPENCTI_JSON_LOGGING` would be ambiguous.
Something else (a library, a test tool) could silently disable the JSON output, and it would differ from pycti's meaning.

### Always add the JSON handler, next to the other handlers

Rejected:

- The meaning of `OPENCTI_JSON_LOGGING` would be ambiguous too.
- A connector with its own handler on stderr would write every record twice, in two formats.
- The SDK would set the level of a setup it does not own.

<br>

## References

- [Python logging HOWTO: configuring logging for a library](https://docs.python.org/3/howto/logging.html#configuring-logging-for-a-library)
- [Python `logging.LoggerAdapter`](https://docs.python.org/3/library/logging.html#loggeradapter-objects)
- [pycti logger (`opencti_logger.py`)](https://github.com/OpenCTI-Platform/opencti/blob/master/client-python/pycti/utils/opencti_logger.py)
