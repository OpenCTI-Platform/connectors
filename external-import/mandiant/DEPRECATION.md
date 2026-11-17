# Mandiant connector: deprecation notice

> [!CAUTION]
> The Mandiant connector is **deprecated**. Support ends in April 2027 and it
> will be removed in a future release. Migrate to [`google-ti-feeds`](../google-ti-feeds).

Values in `[...]` are placeholders for information that is not known yet. They
are filled in as soon as it is.

## Status

| Item | Value |
|------|-------|
| Connector | `external-import/mandiant` (image `opencti/connector-mandiant`) |
| Deprecated since | [DEPRECATION_DATE] |
| End of support | April 2027 |
| Planned removal | Not scheduled yet. It will be announced in advance. |
| Last supported release | [LAST_SUPPORTED_VERSION] |
| Support until April 2027 | [SUPPORT_POLICY] |
| Recommended alternative | [`google-ti-feeds`](../google-ti-feeds) |
| Contact | [SUPPORT_CONTACT] |

## What changes for you

- Until the removal the connector keeps running. Support ends in April 2027 (what is still fixed until then: [SUPPORT_POLICY]).
- It logs a `[DEPRECATED]` warning at startup and at every run, and prints a
  `FutureWarning` on stderr when the process starts.
- The connector is listed as "Mandiant (Deprecated)" in the catalog.
- On the removal, the source code and the image `opencti/connector-mandiant`
  are no longer maintained or published. The date will be announced here and on
  the channels below before it happens.

## How to migrate

1. Deploy [`google-ti-feeds`](../google-ti-feeds) following its README.
2. [MIGRATION_STEP_2]
3. Stop and remove the `connector-mandiant` container once [`google-ti-feeds`](../google-ti-feeds) runs.

Data already imported stays in OpenCTI. Whether [`google-ti-feeds`](../google-ti-feeds) reuses the
existing entities (same author, same deterministic IDs) is: [DATA_CONTINUITY].

## Announcement text

Ready to publish once the placeholders are filled in.

**Title:** Mandiant connector deprecated, use google-ti-feeds

**Body:**

> The Mandiant connector for OpenCTI (`external-import/mandiant`) is deprecated.
> Support ends in April 2027 and it will be removed in a future release. The
> removal date will be announced in advance.
>
> **What you need to do:** migrate to [`google-ti-feeds`](../google-ti-feeds). Until the removal, the
> connector keeps running and logs a deprecation warning at every run.
>
> **What stays the same:** data already imported into OpenCTI is kept.
>
> **Where to find help:** migration steps are in
> [DEPRECATION.md](https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/mandiant/DEPRECATION.md).
> Questions and feedback: [SUPPORT_CONTACT].

**Short version (chat, release notes):**

> ⚠️ Mandiant connector deprecated, support ends April 2027, use google-ti-feeds. Removal date
> to be announced.

## Where this deprecation is marked

Kept so the removal is a mirror image of the deprecation.

| Channel | Location |
|---------|----------|
| Catalog and composer | `__metadata__/connector_manifest.json` (`title`, `description`, `short_description`) |
| README | banner and "Deprecation notice" section in `README.md` |
| Runtime | `src/deprecation_notice.py`, called from `src/connector/__main__.py` and `src/connector/base.py` |
| Image | `org.opencontainers.image.description` label in `Dockerfile` |
| Deployment samples | header comment in `docker-compose.yml`, `src/.env.sample`, `src/config.yml.sample` |
