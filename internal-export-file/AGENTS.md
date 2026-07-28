# AGENTS.md — Internal Export File Connectors

Scope: everything under `internal-export-file/`. Read the repo-root
[`AGENTS.md`](../AGENTS.md) first (universal rules: STIX IDs, config, logging,
formatting/linting/tests).

> **No dedicated spec doc exists yet** for this connector type (unlike
> external-import/internal-enrichment/stream, which have `docs/02-04`). The rules
> below are distilled from [`templates/internal-export-file`](../templates/internal-export-file).
> Several existing connectors here (e.g. `export-file-csv`) predate the connectors-sdk
> and use the legacy `get_config_variable` pattern — **don't copy that pattern for new
> connectors**; follow the template instead, which uses `ConnectorSettings`/Pydantic
> like every other connector type.

## What this connector type does

Triggered when a user requests an export from the OpenCTI UI. The connector receives
the export request, generates a file (CSV, STIX, PDF, etc.), and pushes it back into
OpenCTI via a direct API call — it does not send a STIX bundle back through the
worker queue like other connector types do.

## Class shape

```python
class MyExportConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper

    def process_message(self, data: dict) -> str:
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        file_name = data["file_name"]
        export_type = data["export_type"]
        file_markings = data["file_markings"]
        export_scope = data["export_scope"]       # "query" | "selection" | "single"
        access_filter = data.get("access_filter")

        # ... build the export content (json_bundle, csv bytes, etc.) ...

        self.helper.api.stix_cyber_observable.push_list_export(
            entity_id, entity_type, file_name, file_markings, json_bundle, list_filters,
        )
        return "Export done"

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
```

## Message payload (`data` dict)

| Key             | Meaning                                                                 |
| ----------------- | -------------------------------------------------------------------- |
| `entity_id`      | Root entity being exported (absent for global/query exports)           |
| `entity_type`    | Determines which `push_list_export` client to call (see below)         |
| `file_name`      | Name to give the generated file                                        |
| `export_type`    | Requested format/flavor (connector-specific)                           |
| `file_markings`  | Markings to attach to the generated file                               |
| `export_scope`   | `"query"`, `"selection"`, or `"single"` — what set of entities to export |
| `access_filter`  | Filter to apply when resolving the entities to export                  |

## Pushing the result back — pick the right client by `entity_type`

- `self.helper.api.stix_cyber_observable.push_list_export(...)` — observables
- `self.helper.api.stix_domain_object.push_list_export(...)` — domain objects
- `self.helper.api.stix_core_object.push_list_export(...)` — generic core objects

For `export_scope == "selection"`, resolve the entities via
`self.helper.api_impersonate.stix2.export_selected(entities_list, export_type, access_filter)`
before pushing.

## Still applies from the root rules

Structured logging via `self.helper.connector_logger`, no hardcoded secrets, formatting/
linting/tests before commit. STIX ID determinism applies if you construct STIX objects
as part of building the export (e.g. `export-file-stix`).

## Reference implementation

[`templates/internal-export-file`](../templates/internal-export-file) for the current
(connectors-sdk based) scaffold to copy from.
