---
name: connector-manager-supported-migration
description: >-
  Migrate a legacy OpenCTI connector to manager-supported mode without
  restructuring it: Pydantic settings on connectors-sdk, wired into the
  existing code, manifest flag, generated config schema and tests, one commit
  per step. Use when asked to migrate a connector to manager-supported or
  catalog mode, to replace get_config_variable or config.yml loading with
  ConnectorSettings / BaseConnectorSettings, or to migrate several connectors
  in parallel. Not for building a new connector or for the full verified
  rework (package restructuring, schedule_iso, logging, STIX IDs).
---

# Connector manager-supported migration

The procedure lives in [references/procedure.md](references/procedure.md).
It is the single source of truth: this file only says how to run it.

## Collect the inputs

- **Connector path(s)**, for example `external-import/vxvault`.
- **GitHub issue number** for each connector: every commit message ends with
  `(#<issue>)` and each connector ships as its own pull request. Ask for it if
  the request does not give it.
- Any preference that departs from the procedure (skip a step, keep a legacy
  variable name, ...). Pass it on as is.

If the request only asks what manager-supported means or how the migration
works, answer from the procedure without running it.

## One connector

If your tool can delegate to the `connector-manager-supported-migrator` agent
(defined in `.claude/agents/`), hand it the connector path, the issue number
and any preferences, then relay its report.

Otherwise, read `references/procedure.md` and follow it step by step in the
current working copy.

## Several connectors

Run one migration per connector, in parallel, each in its own working copy so
the runs never touch the same files:

1. Create an isolated working copy per connector, from up-to-date `master`,
   next to the repository:
   - git: `git worktree add -b <branch> ../connectors-<name> origin/master`
   - jj: `jj workspace add --name <name> -r master ../connectors-<name>`
2. Start one `connector-manager-supported-migrator` agent per connector in the
   same turn, each given its working-copy directory, connector path and issue
   number. Without agent support, migrate the connectors one after another.
3. Collect each report and summarize per connector: commits, test results,
   follow-ups.
4. Remove each working copy once its migration is reported. The commits
   remain in the repository.
   - git: `git worktree remove ../connectors-<name>` (the branch stays)
   - jj: `jj workspace forget <name> && rm -rf ../connectors-<name>`; set a
     bookmark on the migration commits first if they need a name to be found.

## After the migration

The migration does not push or open a pull request. Before opening one, follow
the "Pull requests" checklist in `AGENTS.md` (one issue per pull request,
signed commits, template, labels).
