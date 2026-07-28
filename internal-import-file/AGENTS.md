# AGENTS.md — Internal Import File Connectors

Scope: everything under `internal-import-file/`. Read the repo-root
[`AGENTS.md`](../AGENTS.md) first (universal rules: STIX IDs, config, logging,
formatting/linting/tests).

> **No dedicated spec doc exists yet** for this connector type (unlike
> external-import/internal-enrichment/stream, which have `docs/02-04`). The rules
> below are distilled from [`templates/internal-import-file`](../templates/internal-import-file)
> and real connectors (e.g. `import-file-stix`) — treat as lower-confidence than the
> documented types, and prefer reading a couple of existing connectors in this folder
> before writing new logic.

## What this connector type does

Triggered when a user uploads a file into OpenCTI whose MIME type (or STIX type)
matches the connector's `scope`. The connector fetches the raw file content, parses/
converts it, and sends the result back as a STIX bundle — mechanically identical to
internal-enrichment (same `helper.listen()` push model), but the payload is a file
rather than an existing entity.

## Class shape

```python
class MyImportConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper

    def process_message(self, data: dict) -> str:
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch
        entity_id = data.get("entity_id")            # set only for contextual import
        bypass_validation = data["bypass_validation"]

        file_content = self.helper.api.fetch_opencti_file(file_uri)
        # ... parse / convert file_content to a STIX bundle ...
        return self.helper.send_stix2_bundle(
            file_content,
            bypass_validation=bypass_validation,
            file_name=data["file_id"],
            entity_id=entity_id,
            file_markings=data.get("file_markings", []),
        )

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
```

## Message payload (`data` dict)

| Key                 | Meaning                                                              |
| ------------------- | --------------------------------------------------------------------- |
| `file_fetch`        | Path to append to `self.helper.opencti_url` to download the file      |
| `file_mime`         | MIME type of the uploaded file — branch conversion logic on this      |
| `file_id`           | Pass through as `file_name` when sending the resulting bundle          |
| `entity_id`         | Present for **contextual import** (import directly into a container: Report, Case, etc.) — absent otherwise |
| `bypass_validation` | Pass straight through to `send_stix2_bundle(bypass_validation=...)`    |
| `file_markings`     | Markings to attach to the imported file/bundle                        |

## Contextual import

When `entity_id` is set, merge the parsed objects into the target container's
`object_refs` instead of creating a standalone bundle (see `import-file-stix`'s
`_update_container` for the reference pattern: read the container, append new object
refs, re-attach).

## Still applies from the root rules

- Any STIX object you construct while parsing the file must use a deterministic ID
  (connectors-sdk model or `stix2` + `pycti.generate_id()`).
- `connector.scope` here means MIME type(s) / STIX object type(s) that trigger the
  connector — set it precisely so unrelated uploads aren't routed to you.

## Reference implementation

[`templates/internal-import-file`](../templates/internal-import-file) for the scaffold;
`internal-import-file/import-file-stix/src/connector/connector.py` for a real,
non-trivial example (STIX 1.2→2.1 elevation, contextual import).
