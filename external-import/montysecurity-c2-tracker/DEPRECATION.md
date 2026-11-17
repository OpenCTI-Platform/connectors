# Monty Security C2 Tracker connector: deprecation notice

> [!CAUTION]
> The Monty Security C2 Tracker connector is **deprecated** and will be removed
> in a future release. It already **no longer imports data**, because its
> upstream source was removed. No replacement connector is available.

Values in `[...]` are placeholders for information that is not known yet. They
are filled in as soon as it is.

## Status

| Item | Value |
|------|-------|
| Connector | `external-import/montysecurity-c2-tracker` (image `opencti/connector-montysecurity-c2-tracker`) |
| Deprecated since | [DEPRECATION_DATE] |
| Reason | The upstream repository `montysecurity/C2-Tracker` is archived and its `data` directory returns 404. Tracked in issue #8169. |
| Planned removal | Not scheduled yet. It will be announced in advance. |
| Last working release | [LAST_WORKING_VERSION] |
| Support until removal | No fix is possible: the data source no longer exists. |
| Recommended alternative | None available. |
| Contact | [SUPPORT_CONTACT] |

## What changes for you

- The connector cannot import data any more. Each run fails with a clear error
  in the Works tab instead of succeeding with an empty bundle.
- It logs a `[DEPRECATED]` warning at startup and at every run, and prints a
  `FutureWarning` on stderr when the process starts.
- The connector is listed as "MontySecurity C2 Tracker (Deprecated)" in the
  catalog.
- Its behaviour and configuration keys are unchanged.
- On the removal, the source code and the image
  `opencti/connector-montysecurity-c2-tracker` are no longer maintained or
  published. The date will be announced here and on the channels below before
  it happens.

## How to migrate

There is no replacement connector, so the steps are about cleaning up.

1. Stop and remove the `connector-c2tracker` container, or the process started
   from `config.yml`.
2. Remove the connector from `Data management` -> `Ingestion` -> `Connectors`
   in OpenCTI, so that it no longer shows as inactive.
3. [MIGRATION_STEP_3]

Data already imported (Malware, IP address observables and their relationships,
authored by Monty Security) stays in OpenCTI. It is not updated any more, so
review it before relying on it for detection. Whether it should be deleted is:
[DATA_RETENTION_ADVICE].

## Announcement text

Ready to publish once the placeholders are filled in.

**Title:** Monty Security C2 Tracker connector deprecated, no replacement

**Body:**

> The Monty Security C2 Tracker connector for OpenCTI
> (`external-import/montysecurity-c2-tracker`) is deprecated as of
> [DEPRECATION_DATE]. It will be removed in a future release. The removal date
> will be announced in advance.
>
> **Why:** the upstream C2-Tracker repository is archived and its data was
> removed, so the connector no longer imports anything.
>
> **What you need to do:** stop the connector. No replacement connector is
> available.
>
> **What stays the same:** data already imported into OpenCTI is kept, but it is
> no longer updated.
>
> **Where to find help:** see
> [DEPRECATION.md](https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/montysecurity-c2-tracker/DEPRECATION.md).
> Questions and feedback: [SUPPORT_CONTACT].

**Short version (chat, release notes):**

> ⚠️ Monty Security C2 Tracker connector deprecated: its upstream data is gone
> and there is no replacement. Removal date to be announced.

## Where this deprecation is marked

Kept so the removal is a mirror image of the deprecation.

| Channel | Location |
|---------|----------|
| Catalog and composer | `__metadata__/connector_manifest.json` (`title`, `description`, `short_description`) |
| README | banner and "Deprecation notice" section in `README.md` |
| Runtime | `src/deprecation_notice.py`, called from `src/main.py` and `src/connector/connector.py` |
| Image | `org.opencontainers.image.description` label in `Dockerfile` |
| Deployment samples | header comment in `docker-compose.yml`, `.env.sample`, `config.yml.sample` |
