# Group-IB connector: deprecation notice

> [!CAUTION]
> The Group-IB connector is **deprecated** and will be removed in a future
> release. Migrate to [`group-ib-ti`](../group-ib-ti).

Values in `[...]` are placeholders for information that is not known yet. They
are filled in as soon as it is.

## Status

| Item | Value |
|------|-------|
| Connector | `external-import/group-ib` (image `opencti/connector-group-ib`) |
| Deprecated since | [DEPRECATION_DATE] |
| Planned removal | Not scheduled yet. It will be announced in advance. |
| Last supported release | [LAST_SUPPORTED_VERSION] |
| Support until removal | [SUPPORT_POLICY] |
| Recommended alternative | [`group-ib-ti`](../group-ib-ti) ("Group-IB Threat Intelligence", image `opencti/connector-group-ib-ti`) |
| Contact | [SUPPORT_CONTACT] |

## What changes for you

- Until the removal the connector keeps running. Support level: [SUPPORT_POLICY].
- It logs a `[DEPRECATED]` warning at startup and at every run, and prints a
  `FutureWarning` on stderr when the process starts.
- The connector is listed as "Group-IB (Deprecated)" in the catalog.
- On the removal, the source code and the image `opencti/connector-group-ib`
  are no longer maintained or published. The date will be announced here and on
  the channels below before it happens.

## How to migrate

1. Deploy [`group-ib-ti`](../group-ib-ti) following its README. Both connectors
   read the Group-IB credentials from `TI_API_USERNAME` and `TI_API_TOKEN`, so
   the same credentials can be reused.
2. [MIGRATION_STEP_2]
3. Stop and remove the `connector-group-ib` container once `group-ib-ti` runs.

Data already imported stays in OpenCTI. Whether `group-ib-ti` reuses the
existing entities (same author, same deterministic IDs) is: [DATA_CONTINUITY].

## Announcement text

Ready to publish once the placeholders are filled in.

**Title:** Group-IB connector deprecated, use group-ib-ti

**Body:**

> The Group-IB connector for OpenCTI (`external-import/group-ib`) is deprecated
> as of [DEPRECATION_DATE]. It will be removed in a future release. The removal
> date will be announced in advance.
>
> **What you need to do:** migrate to `group-ib-ti` (Group-IB Threat
> Intelligence). Until the removal, the connector keeps running and logs a
> deprecation warning at every run.
>
> **What stays the same:** data already imported into OpenCTI is kept.
>
> **Where to find help:** migration steps are in
> [DEPRECATION.md](https://github.com/OpenCTI-Platform/connectors/blob/master/external-import/group-ib/DEPRECATION.md).
> Questions and feedback: [SUPPORT_CONTACT].

**Short version (chat, release notes):**

> ⚠️ Group-IB connector deprecated, use `group-ib-ti`. Removal date to be
> announced.

## Where this deprecation is marked

Kept so the removal is a mirror image of the deprecation.

| Channel | Location |
|---------|----------|
| Catalog and composer | `__metadata__/connector_manifest.json` (`title`, `description`, `short_description`) |
| README | banner and "Deprecation notice" section in `README.md` |
| Runtime | `src/deprecation_notice.py`, called from `src/main.py` and `src/lib/external_import.py` |
| Image | `org.opencontainers.image.description` label in `Dockerfile` |
| Deployment samples | header comment in `docker-compose.yml`, `.env.sample`, `src/config.yml.sample` |
