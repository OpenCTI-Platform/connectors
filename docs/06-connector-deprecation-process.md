# Deprecating a connector

This is the working procedure for marking a connector as deprecated. It is
informal: it was extracted from the deprecation of `external-import/group-ib`
and will be tightened into a formal ceremony later. Use it as a checklist and
improve it when a step turns out to be wrong.

Deprecation here means: the connector still works, users are told loudly that it
will be removed, and they are told what to do. Removal is a separate, later
change (see [Removal](#removal)).

## Decide first

Fill these in before touching code. Each one becomes a placeholder token that
appears in many files, so settle them or keep the tokens until they are known.

| Token | Meaning |
|-------|---------|
| `[DEPRECATION_DATE]` | Date the deprecation takes effect (merge or release date) |
| `[REPLACEMENT]` | Recommended alternative, with a link (required) |
| `[REMOVAL_DATE]` | Date the connector is removed (optional) |
| `[DEPRECATION_ISSUE_URL]` | The GitHub issue that tracks it (optional) |
| `[LAST_SUPPORTED_VERSION]` | Last release users can rely on |
| `[SUPPORT_POLICY]` | What is still fixed until removal |
| `[SUPPORT_CONTACT]` | Where users ask questions |
| `[MIGRATION_STEP_N]`, `[DATA_CONTINUITY]` | Migration details for `DEPRECATION.md` |

The removal date and the issue URL are optional. When they are not known, drop
them from the messages instead of leaving a token, and write "removed in a
future release, date announced in advance". `external-import/group-ib` was
deprecated this way: only the replacement (`group-ib-ti`) was known.

The pull request still needs a linked issue (see `AGENTS.md`), even when its
URL is not repeated in the user-facing text.

## Checklist

Replace `<type>/<name>` with the connector path. Reference implementation:
`external-import/group-ib`.

### 1. Manifest and catalog

File: `<type>/<name>/__metadata__/connector_manifest.json`.

- [ ] Append ` (Deprecated)` to `title`.
- [ ] Start `description` with the deprecation sentence: `⚠️ DEPRECATED: ...`,
  including the replacement, and the removal date when it is known.
- [ ] Start `short_description` with `⚠️ DEPRECATED, use <replacement>. ...`.
  Keep it at 250 characters or fewer.
- [ ] Do not touch `verified`, `last_verified_date`, `manager_supported`,
  `slug` or `container_image`. Maintainers own the first three, and the last
  two must stay unique and stable.

The first words matter most: the XTM composer and the catalog show the start of
these fields.

### 2. Runtime

- [ ] Add a small module (`src/deprecation_notice.py` in group-ib) holding the
  tokens and the message, so there is one place to edit. Do not name it
  `deprecation`, which shadows a PyPI package.
- [ ] Emit `warnings.warn(..., FutureWarning)` at process start, before the
  configuration is validated. `DeprecationWarning` is hidden by default.
- [ ] Log at WARNING level, with a static message and a context dict, at startup
  and at the start of every run. Never log it as an error.
- [ ] Prefix the names of the works created in OpenCTI with `[DEPRECATED]` so the
  notice shows in the platform UI. Enrichment and stream connectors have no work
  name: log only.
- [ ] Do not change the connector behaviour, defaults or configuration keys.
  Changing the default `name` would alter the generated schema and docs.
- [ ] Add unit tests for the warning and the log call.

### 3. Documentation

- [ ] `README.md`: add `(Deprecated)` to the title, a `[!CAUTION]` banner right
  under it, and a "Deprecation notice" section with the token table.
- [ ] Add `DEPRECATION.md` next to the README: status table, what changes,
  migration steps, announcement text, and the "Where this deprecation is
  marked" table.
- [ ] Add a one-line header comment to `docker-compose.yml`, `.env.sample`
  and `config.yml.sample`.
- [ ] Add an `org.opencontainers.image.description` label to the `Dockerfile`.
- [ ] Add a `CHANGELOG.md` with a `Deprecated` entry under `Unreleased`. The
  repository changelog is generated from commit titles (`cliff.toml`), so the
  commit title must say it too.
- [ ] Do not edit generated files: `connector_config_schema.json`,
  `CONNECTOR_CONFIG_DOC.md` and the root `manifest.json`.

### 4. Communication

- [ ] Write the announcement in `DEPRECATION.md` (long and short version).
- [ ] Publish it on the channels the team uses: [ANNOUNCEMENT_CHANNELS].
- [ ] Post the link in the tracking issue.
- [ ] Tell support and customer success, with the migration steps.

### 5. Validate

Run from the repository root, replacing the path.

```bash
uvx isort==7.0.0 --profile black --line-length 88 external-import/myconnector
uvx black==26.5.1 external-import/myconnector
uvx flake8 --ignore=E,W external-import/myconnector
bash run_test.sh ./external-import/myconnector/tests/test-requirements.txt
```

- [ ] Every placeholder is resolved, or consciously left for a follow-up. List
  what remains:

  ```bash
  grep -rnE "\[(DEPRECATION_DATE|REMOVAL_DATE|REPLACEMENT|LAST_SUPPORTED_VERSION|SUPPORT_POLICY|DEPRECATION_ISSUE_URL|SUPPORT_CONTACT|MIGRATION_STEP_[0-9]+|DATA_CONTINUITY|ANNOUNCEMENT_CHANNELS)\]" external-import/myconnector --exclude-dir=.venv
  ```

- [ ] The manifest is valid JSON and the image builds.

### 6. Commit and PR

- [ ] Commit title: `chore(<name>): deprecate the connector (#<issue>)`, signed.
- [ ] One issue per PR, labels as in `AGENTS.md`.

## Removal

Announce the removal date in advance, on the same channels as the deprecation.
When that date is reached, do the reverse in a separate PR: delete the
connector directory, check no workflow or documentation still references it,
and announce the removal on the same channels as the deprecation. The
"Where this deprecation is marked" table in `DEPRECATION.md` lists everything
that referenced the deprecation.

## Open questions for the formal ceremony

- Minimum notice period between deprecation and removal.
- Who approves a deprecation, and who announces it.
- Whether the manifest should get a machine-readable `deprecated` field instead
  of relying on the title and description text.
- Whether the connector linter should check that a deprecated connector
  carries the markers above.
