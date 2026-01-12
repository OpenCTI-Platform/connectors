from __future__ import annotations

"""OpenCTI Pravda Dataset connector entrypoint.

This module wires together:
- configuration loading (environment variables)
- file discovery + CSV reading
- row-to-STIX mapping
- batching + stateful resume (per-file cursor)
- delivery to OpenCTI via `pycti` (RabbitMQ-backed)

The goal is to be safe to re-run: deterministic STIX IDs + persisted cursors
prevent re-ingesting the same rows.
"""

import json
import os
import time
import traceback
from pathlib import Path

from pravda_dataset.config import ConfigError, load_config
from pravda_dataset.logging_utils import configure_logging
from pravda_dataset.dataset_files import discover_dataset_files
from pravda_dataset.dataset_reader import RowSkip, iter_rows
from pravda_dataset.dates import DateParseError
from pravda_dataset.author import checkfirst_identity
from pravda_dataset.bundler import dedupe_objects, make_bundle
from pravda_dataset.reporting import RunReport, SkipReason
from pravda_dataset.stix_mapping import map_row_to_stix
from pravda_dataset.state import (
    get_file_cursor,
    load_state_from_helper,
    save_state_to_helper,
    set_file_cursor,
)


def _import_pycti():
    """Import `pycti` lazily and raise a helpful error if missing.

    We keep this import inside a function so tooling (linters/tests) can still
    import this module even if `pycti` isn't installed in the current env.
    """
    try:
        from pycti import OpenCTIConnectorHelper  # type: ignore

        return OpenCTIConnectorHelper
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "pycti is required to run this connector. Install dependencies from opencti-connector-pravda-dataset/requirements.txt"
        ) from exc


def run_once(helper, config):
    """Run a single ingestion pass.

    - Discovers dataset files.
    - For each file, resumes from the last saved cursor (row index).
    - Builds STIX objects and sends them in bundles of `config.batch_size`.
    - Updates state after each successfully sent bundle.
    """
    report = RunReport()
    dataset_root = Path(config.dataset_path)
    files = discover_dataset_files(dataset_root)
    if not files:
        helper.log_info("No dataset files found.")
        helper.log_info(f"Run summary: {report.to_summary()}")
        return

    # Best-effort "work" tracking in OpenCTI UI (not all helper versions expose it).
    work_id = None
    try:
        api = getattr(helper, "api", None)
        work = getattr(api, "work", None)
        initiate = getattr(work, "initiate_work", None)
        if callable(initiate):
            try:
                work_id = initiate(config.connector_id, "Pravda Dataset ingestion")
            except TypeError:
                work_id = initiate(config.connector_id)
    except Exception:  # noqa: BLE001
        work_id = None

    # Load persisted per-file cursors (if any) so we can resume safely.
    state = load_state_from_helper(helper)

    def _log_debug(msg: str) -> None:
        if hasattr(helper, "log_debug"):
            helper.log_debug(msg)
        else:
            helper.log_info(msg)

    try:
        for file_path in files:
            report.files_seen += 1
            # We store cursors keyed by a stable relative path using POSIX separators.
            file_key = str(
                file_path.resolve().relative_to(dataset_root.resolve())
            ).replace("\\", "/")
            cursor = get_file_cursor(state, file_key)

            author = None
            author_id = None
            bundle_objects = []
            rows_in_bundle = 0
            last_row_number = None
            try:
                for row in iter_rows(
                    config=config,
                    dataset_root=dataset_root,
                    file_path=file_path,
                    start_cursor=cursor,
                    report=report,
                ):
                    report.rows_seen += 1
                    # We create an author identity once per file/run and attach it
                    # to all objects for consistent attribution.
                    if author is None:
                        author = checkfirst_identity(
                            source_file=row.source_file, row_number=row.row_number
                        )
                        author_id = author["id"]
                        bundle_objects = [author]

                    try:
                        bundle_objects.extend(
                            map_row_to_stix(row=row, author_identity_id=author_id)
                        )
                    except DateParseError as exc:
                        report.skip(SkipReason.ROW_INVALID_PUBLICATION_DATE)
                        _log_debug(
                            f"Skip row {row.source_file}:{row.row_number} (invalid Publication Date): {exc}"
                        )
                        continue
                    except Exception as exc:  # noqa: BLE001
                        report.skip(SkipReason.ROW_MAPPING_ERROR)
                        helper.log_error(
                            f"Skip row {row.source_file}:{row.row_number} (mapping error): {exc}"
                        )
                        continue

                    report.rows_mapped += 1
                    last_row_number = row.row_number
                    rows_in_bundle += 1

                    if rows_in_bundle >= config.batch_size:
                        try:
                            # Dedupe helps avoid re-sending identical objects within
                            # a bundle (e.g., repeated alternates).
                            bundle = make_bundle(dedupe_objects(bundle_objects))
                            # `pycti` expects a JSON string (it calls json.loads()).
                            if not isinstance(bundle, (str, bytes, bytearray)):
                                bundle = json.dumps(bundle)
                            helper.send_stix2_bundle(bundle)
                            report.bundles_sent += 1
                        except Exception as exc:  # noqa: BLE001
                            report.error(SkipReason.BUNDLE_SEND_ERROR)
                            helper.log_error(
                                f"Bundle send failed for {file_key}: {exc}"
                            )
                            raise

                        # Persist progress only after a successful send.
                        state = set_file_cursor(state, file_key, last_row_number)
                        save_state_to_helper(helper, state)

                        bundle_objects = [author]
                        rows_in_bundle = 0
            except RowSkip as exc:
                report.skip(SkipReason.HEADER_INVALID)
                helper.log_error(f"Skip file {file_key} (invalid header): {exc}")
                continue
            except Exception as exc:  # noqa: BLE001
                report.error(SkipReason.FILE_READ_ERROR)
                helper.log_error(f"Error processing file {file_key}: {exc}")
                continue

            report.files_processed += 1

            if author is None:
                continue

            if rows_in_bundle > 0 and last_row_number is not None:
                try:
                    bundle = make_bundle(dedupe_objects(bundle_objects))
                    if not isinstance(bundle, (str, bytes, bytearray)):
                        bundle = json.dumps(bundle)
                    helper.send_stix2_bundle(bundle)
                    report.bundles_sent += 1
                except Exception as exc:  # noqa: BLE001
                    report.error(SkipReason.BUNDLE_SEND_ERROR)
                    helper.log_error(f"Bundle send failed for {file_key}: {exc}")
                    raise
                # Final cursor update for this file.
                state = set_file_cursor(state, file_key, last_row_number)
                save_state_to_helper(helper, state)
    finally:
        helper.log_info(f"Run summary: {report.to_summary()}")

        if work_id is not None:
            try:
                api = getattr(helper, "api", None)
                work = getattr(api, "work", None)
                to_processed = getattr(work, "to_processed", None)
                if callable(to_processed):
                    try:
                        to_processed(work_id, f"Completed run: {report.to_summary()}")
                    except TypeError:
                        to_processed(work_id)
            except Exception:  # noqa: BLE001
                pass


def main() -> None:
    """CLI entrypoint.

        Run modes:
    - `once`: ingest once and exit.
    - `loop`: ingest repeatedly with a sleep interval.
    """
    try:
        config = load_config(os.environ)
    except ConfigError as exc:
        raise SystemExit(str(exc))

    configure_logging(config.connector_log_level)

    # Import `pycti` only when we're actually going to run.
    OpenCTIConnectorHelper = _import_pycti()
    try:
        # `pycti` reads additional settings from env (notably MQ_* overrides),
        # but it still needs the OpenCTI + connector identity config dict.
        helper = OpenCTIConnectorHelper(
            {
                "opencti": {"url": config.opencti_url, "token": config.opencti_token},
                "connector": {
                    "id": config.connector_id,
                    "type": config.connector_type,
                    "name": config.connector_name,
                    "scope": config.connector_scope,
                    "log_level": config.connector_log_level,
                },
            }
        )
    except BaseException:  # noqa: BLE001
        # If helper creation fails (bad token / connectivity / missing deps),
        # print a full traceback to make local debugging easier.
        traceback.print_exc()
        raise

    if config.run_mode == "once":
        run_once(helper, config)
        return

    while True:
        try:
            run_once(helper, config)
        except NotImplementedError:
            helper.log_info("Connector pipeline not implemented yet.")
            return
        except Exception as exc:  # noqa: BLE001
            helper.log_error(str(exc))

        # Interval is configured in minutes.
        time.sleep(max(1, int(config.interval_minutes)) * 60)


if __name__ == "__main__":
    main()
