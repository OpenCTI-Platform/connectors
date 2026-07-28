# AGENTS.md — External Import Connectors

Scope: everything under `external-import/`. Read the repo-root [`AGENTS.md`](../AGENTS.md)
first (universal rules: STIX IDs, config, logging, formatting/linting/tests). Full spec:
[`docs/02-external-import-specifications.md`](../docs/02-external-import-specifications.md).

## What this connector type does

Pulls data from an external source (API, feed, file) on a schedule and imports it into
OpenCTI as STIX 2.1 objects. Pull-based, stateful (tracks what's been imported),
autonomous (no user trigger needed).

## Class shape

```python
class MyConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = MyClient(...)                 # external API client
        self.converter_to_stix = ConverterToStix(...)  # STIX conversion

    def _collect_intelligence(self) -> list: ...    # fetch + convert to STIX, returns list of objects
    def process_message(self) -> None: ...          # state + work management + send bundle
    def run(self) -> None:
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
```

## Scheduling: use `schedule_process()`, never a manual loop

Since OpenCTI 6.2.12, **do not** write `while True: ... time.sleep(...)` or implement
Run-and-Terminate manually. `self.helper.schedule_process(...)` handles both the
periodic scheduled mode and Run & Terminate mode (triggered by
`connector.run_and_terminate: true` or a zero `duration_period`), including flushing
state via `force_ping()` before exit. `duration_period` is an ISO-8601 duration
(`PT1H`, `PT5M`...) converted to seconds via `.total_seconds()`.

The scheduler also auto-checks `connector.queue_threshold` (MB) and pauses
("Buffering" mode, visible in the OpenCTI UI) if the RabbitMQ queue is too full —
you don't need to implement backpressure yourself.

## Work management — always wrap sends in a work

```python
work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)
# ... send bundle with work_id=work_id ...
self.helper.api.work.to_processed(work_id, f"Imported {len(stix_objects)} objects")
```
Only update state (`self.helper.set_state(...)`) **after** successful completion, so a
failed run retries with the same parameters instead of silently skipping data.

## State: use timestamps/ISO-8601, resume incrementally

Store `last_run_start` / `last_run_with_data` (or a cursor / processed-ID set for
paginated APIs) — always with explicit timezone. Prefer **relative** ISO-8601
durations for `import_from_date`-style config (e.g. `P30D`) over absolute dates —
they keep configs portable and don't degrade as the platform ages.

## Bundle rules

- Always include the **author** and **TLP marking** objects in every bundle sent.
- Use `cleanup_inconsistent_bundle=True` on `send_stix2_bundle(...)` — but then *every*
  bundle must carry its own author/markings, or you'll get `MISSING_REFERENCE_ERROR`.
- Batch large datasets (200k+ entities): ~500 objects/batch, **one `work` per batch**,
  update state after each batch so a mid-run failure resumes instead of restarting.
- Keep single bundles under ~10,000 objects.

## Deduplication — beyond generateId

Besides the root rule (always use deterministic IDs), know the platform's upsert
semantics: incoming data only overwrites an existing entity if its **Confidence Level**
is ≥ the existing one's. Streams/feeds can't set a confidence level per-object, so a
high-confidence source will always win — be deliberate about the confidence you send.

## Rate limiting

```python
from limiter import Limiter
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

self.rate_limiter = Limiter(rate=10, capacity=20, bucket="my_connector")

@retry(stop=stop_after_attempt(3), wait=wait_exponential_jitter(initial=1, max=60, jitter=1))
def _request(self, endpoint): ...
```

## Reference implementation

A full working example is in [`docs/02-external-import-specifications.md#complete-example`](../docs/02-external-import-specifications.md#complete-example)
and the scaffold at [`templates/external-import`](../templates/external-import).
