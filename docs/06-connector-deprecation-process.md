# Deprecating a connector

**Document:** 06-connector-deprecation-process.md
**Applies to:** All connector types

This page explains how to mark a connector as deprecated. The procedure is
informal. It comes from the deprecation of `external-import/group-ib` in favor
of `group-ib-ti`, and it will be tightened once more connectors have gone
through it. If a step turns out to be wrong or missing, fix this page in the
same pull request.

## Table of Contents

- [What deprecation means](#what-deprecation-means)
- [Before you start](#before-you-start)
- [Where to mark the deprecation](#where-to-mark-the-deprecation)
- [Before opening the pull request](#before-opening-the-pull-request)
- [Announcing it](#announcing-it)
- [Removing the connector](#removing-the-connector)
- [Open questions](#open-questions)

---

## What deprecation means

A deprecated connector keeps working. Users are told clearly that it will be
removed and what to use instead, so they have time to move. The connector's
behaviour and configuration do not change.

Removal is a separate, later change. Keeping the two apart means a deprecation
can be merged before anyone has agreed on a removal date.

## Before you start

Gather the following. Most of it will appear in several files, so it is easier
to settle it once.

| Information | Why it matters |
|-------------|----------------|
| Replacement connector | Users need to know where to go. Without one, say so explicitly. |
| Deprecation date | The date the deprecation takes effect, usually the merge or release date. |
| Support until removal | What is still fixed while the connector is deprecated. |
| Contact | Where users can ask questions about the migration. |
| Migration steps | What a user does to move to the replacement, and what happens to data already imported. |

Do not guess any of these. If a value is not known yet, write it as a
`[PLACEHOLDER]` token, for example `[DEPRECATION_DATE]`, so it is easy to find
and fill in later. A wrong date or a wrong replacement in a deprecation notice
is worse than a missing one.

A removal date is optional. When there is none, say that the connector will be
removed in a future release and that the date will be announced in advance.

The pull request still needs a linked issue, as for any change (see
`AGENTS.md`).

## Where to mark the deprecation

Users meet a connector in different places, so mark it in all of them. The
reference implementation is `external-import/group-ib`. Replace
`<type>/<name>` below with the connector path.

### Manifest

In `<type>/<name>/__metadata__/connector_manifest.json`:

- Add ` (Deprecated)` at the end of `title`.
- Start `description` with a deprecation sentence that names the replacement.
- Start `short_description` with the same message, in fewer words. The limit is
  250 characters.

The catalog and the XTM composer show the beginning of these fields, which is
why the deprecation comes first.

Leave `verified`, `last_verified_date`, `manager_supported`, `slug` and
`container_image` alone. Maintainers own the first three, and the last two must
stay stable.

### Runtime

Users who run the connector should see the deprecation without opening the
documentation.

- Add a small module that holds the message and the placeholder tokens, so
  there is one place to edit. In `group-ib` it is `src/deprecation_notice.py`.
  Avoid the name `deprecation`, which shadows a package on PyPI.
- Call `warnings.warn(..., FutureWarning)` at process start, before the
  configuration is validated, so a user with a broken configuration still sees
  it. `DeprecationWarning` is hidden by default, `FutureWarning` is not.
- Log the notice at WARNING level when the connector starts and at the start of
  each run, with a fixed message and the details in the context dictionary. An
  error level would make the connector look broken.
- Add unit tests for the warning and the log call.

Keep the connector's behaviour as it is. In particular, do not rename the works
it creates in OpenCTI and do not change the default connector name or any
configuration key: it would change the generated schema and surprise users who
did not ask for it.

### Documentation and deployment files

- In `README.md`, add `(Deprecated)` to the title, a `[!CAUTION]` banner right
  under it, and a short "Deprecation notice" section.
- Add a `DEPRECATION.md` next to the README with the status, what changes for
  users, the migration steps and the announcement text.
- Add a one-line comment at the top of `docker-compose.yml`, `.env.sample` and
  `config.yml.sample`.
- Add an `org.opencontainers.image.description` label to the `Dockerfile`.

Do not edit generated files: `connector_config_schema.json`,
`CONNECTOR_CONFIG_DOC.md` and the root `manifest.json`. They are rebuilt from the
settings, which a deprecation does not change.

## Before opening the pull request

Run the usual checks from the repository root, with the connector path in place
of `<type>/<name>`:

```bash
uvx isort==7.0.0 --profile black --line-length 88 <type>/<name>
uvx black==26.5.1 <type>/<name>
uvx flake8 --ignore=E,W <type>/<name>
bash run_test.sh ./<type>/<name>/tests/test-requirements.txt
```

Then list the placeholders that remain, and mention them in the pull request
description so the reviewers know they are intentional:

```bash
grep -rnE "\[[A-Z_0-9]+\]" <type>/<name> --include="*.md" --include="*.py"
```

The commit title follows the repository convention, for example
`chore(<name>): deprecate the connector (#<issue>)`.

## Announcing it

The text of the announcement lives in `DEPRECATION.md`, in a long and a short
version, so it is reviewed with the code. Publishing it on the channels the team
uses, and telling support and customer success, happens after the merge. Those
channels are not listed here yet.

## Removing the connector

Announce the removal date in advance, on the same channels as the deprecation.
When the date is reached, do the reverse in a separate pull request: delete the
connector directory and check that no workflow or documentation still points to
it. The table at the end of `DEPRECATION.md` lists the places where the
deprecation was marked.

## Open questions

These are not decided yet:

- The minimum notice period between deprecation and removal.
- Who approves a deprecation and who announces it.
- Whether the manifest should get a machine-readable `deprecated` field instead
  of relying on the title and description text.
- Whether the connector linter should check that a deprecated connector carries
  the markers above.
