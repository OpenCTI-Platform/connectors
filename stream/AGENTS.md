# AGENTS.md — Stream Connectors

Scope: everything under `stream/`. Read the repo-root [`AGENTS.md`](../AGENTS.md) first
(universal rules: STIX IDs, config, logging, formatting/linting/tests). Full spec:
[`docs/04-stream-specifications.md`](../docs/04-stream-specifications.md).

## What this connector type does

Listens to a real-time OpenCTI live stream and synchronizes create/update/delete
events to an external system (SIEM, ticketing, messaging, data warehouse). Real-time,
event-driven, stateless per event.

## Class shape

```python
class MyStreamConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.client = MyExternalClient(...)

    def check_stream_id(self) -> None: ...      # validate config before listening
    def process_message(self, msg) -> None: ...  # route by msg.event
    def run(self) -> None:
        self.helper.listen_stream(message_callback=self.process_message)
```

## Stream must exist before the connector runs

A Live Stream is created in the OpenCTI UI (**Data → Data Sharing → Live Streams**),
which yields a `live_stream_id` (config: `connector.live_stream_id`, env:
`CONNECTOR_LIVE_STREAM_ID`). Validate it's set and not `"ChangeMe"` in
`check_stream_id()`, raising `ValueError` otherwise — call this before `listen_stream`.

## Event types

`msg.event` is one of `"create"`, `"update"`, `"delete"`; `msg.data` carries the STIX
entity representation. Route to dedicated handlers (`_handle_create/_update/_delete`)
rather than one large branch — keeps transformation logic per event type testable.

## Error handling: don't let one bad event kill the listener

```python
except ConnectionError:
    ...  # log, don't raise — message will be redelivered
except ValueError:
    ...  # invalid data — log and skip this message, don't raise
except Exception:
    ...  # log unexpected errors — still don't raise
```
Raising from `process_message` stops the stream consumer for that event but the
connector should keep processing subsequent events. For events that must not be
silently dropped, write to a dead-letter store (e.g. append to a JSONL file) instead
of only logging.

## Idempotency is required

Events can be redelivered (retries, reconnects). Before creating in the external
system, check whether the entity already exists there (e.g. by OpenCTI ID) and update
instead of duplicating:

```python
existing = self.client.get_entity_by_opencti_id(entity_data["id"])
if existing:
    return self._handle_update(entity_data)
```

## Data transformation

Map OpenCTI/STIX fields to the external system's schema in a dedicated
`_transform_entity()` (dispatch by `entity_type`), including TLP extraction
(`objectMarking` → `definition_type == "TLP"`) so you can filter/route by
sensitivity (e.g. send `TLP:RED` only to a secure channel).

## Rate limiting & monitoring

Apply your own token-bucket or `limiter`-based throttling before calling the external
system (stream connectors don't get the external-import scheduler's backpressure), and
log periodic metrics (`events_processed`, `events_failed`) so operators can see
throughput and failure rate over time.

## Reference implementation

Full example in [`docs/04-stream-specifications.md#complete-example`](../docs/04-stream-specifications.md#complete-example)
and the scaffold at [`templates/stream`](../templates/stream).
