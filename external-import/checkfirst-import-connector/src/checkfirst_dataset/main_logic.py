from __future__ import annotations

import sys
from datetime import timezone
from pathlib import Path

from checkfirst_dataset.alternates import parse_alternates
from checkfirst_dataset.dataset_files import discover_dataset_files
from checkfirst_dataset.dataset_reader import RowSkip, iter_rows
from checkfirst_dataset.dates import DateParseError, parse_publication_date
from checkfirst_dataset.reporting import RunReport, SkipReason
from checkfirst_dataset.state import (
    get_file_cursor,
    load_state_from_helper,
    save_state_to_helper,
    set_file_cursor,
)
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings


def _resolve_dataset_root(dataset_path: str) -> Path:
    """Resolve a dataset path.

    The configuration value stays *relative* (as requested), but at runtime we
    resolve it relative to the connector folder (the parent of `src/`).

    This prevents surprises when launching the connector from different working
    directories.
    """

    path = Path(dataset_path)
    if path.is_absolute():
        return path

    main = sys.modules.get("__main__")
    main_file = getattr(main, "__file__", None)
    if not main_file:
        return path

    src_dir = Path(main_file).resolve().parent
    connector_root = src_dir.parent
    return connector_root / path


def run_once(helper, settings: ConnectorSettings) -> None:
    """Run a single ingestion pass.

    - Discovers dataset files.
    - For each file, resumes from the last saved cursor (row index).
    - Builds STIX objects and sends them in bundles of `settings.checkfirst.batch_size`.
    - Updates state after each successfully sent bundle.
    """

    report = RunReport()
    converter = ConverterToStix(helper=helper, tlp_level=settings.checkfirst.tlp_level)
    dataset_root = _resolve_dataset_root(settings.checkfirst.dataset_path)
    files = discover_dataset_files(dataset_root)
    if not files:
        helper.log_info("No dataset files found.")
        helper.log_info(f"Run summary: {report.to_summary()}")
        return

    work_id = None
    try:
        api = getattr(helper, "api", None)
        work = getattr(api, "work", None)
        initiate = getattr(work, "initiate_work", None)
        if callable(initiate):
            try:
                work_id = initiate(
                    settings.connector.id, "Checkfirst dataset ingestion"
                )
            except TypeError:
                work_id = initiate(settings.connector.id)
    except Exception:  # noqa: BLE001
        work_id = None

    if settings.checkfirst.force_reprocess:
        helper.log_info(
            "Force reprocess enabled: ignoring any saved connector state/cursors."
        )
        state = {"files": {}}
    else:
        state = load_state_from_helper(helper)

    def _log_debug(msg: str) -> None:
        if hasattr(helper, "log_debug"):
            helper.log_debug(msg)
        else:
            helper.log_info(msg)

    def _send_bundle(bundle_json: str) -> None:
        """Send a STIX bundle with best-effort template-aligned options."""

        send_kwargs = {"cleanup_inconsistent_bundle": True}
        if work_id is not None:
            send_kwargs["work_id"] = work_id

        try:
            helper.send_stix2_bundle(bundle_json, **send_kwargs)
        except TypeError:
            helper.send_stix2_bundle(bundle_json)

    try:
        for file_path in files:
            report.files_seen += 1
            file_key = str(
                file_path.resolve().relative_to(dataset_root.resolve())
            ).replace("\\", "/")
            cursor = (
                0
                if settings.checkfirst.force_reprocess
                else get_file_cursor(state, file_key)
            )

            if cursor:
                helper.log_info(f"Resume {file_key} from cursor={cursor}")

            author = None
            bundle_objects: list[object] = []
            rows_in_bundle = 0
            last_row_number = None
            rows_yielded = 0

            try:
                for row in iter_rows(
                    config=settings.checkfirst,
                    dataset_root=dataset_root,
                    file_path=file_path,
                    start_cursor=cursor,
                    report=report,
                ):
                    rows_yielded += 1
                    report.rows_seen += 1

                    if author is None:
                        author = converter.author
                        bundle_objects = []

                    try:
                        published_dt_parsed = parse_publication_date(
                            row.publication_date
                        )
                        if published_dt_parsed.tzinfo is None:
                            published_dt_parsed = published_dt_parsed.replace(
                                tzinfo=timezone.utc
                            )

                        channel = converter.create_channel(
                            name=row.source_title,
                            source_url=row.source_url,
                        )
                        media_content = converter.create_media_content(
                            title=row.og_title,
                            description=row.og_description,
                            url=row.url,
                            publication_date=published_dt_parsed,
                        )
                        source_url_obj = converter.create_url(value=row.source_url)

                        publishes = converter.create_relationship(
                            source_id=channel.id,
                            relationship_type="publishes",
                            target_id=media_content.id,
                            start_time=published_dt_parsed,
                        )
                        related_to_source = converter.create_relationship(
                            source_id=channel.id,
                            relationship_type="related-to",
                            target_id=source_url_obj.id,
                        )

                        bundle_objects.extend(
                            [
                                channel,
                                media_content,
                                source_url_obj,
                                publishes,
                                related_to_source,
                            ]
                        )

                        for alt in parse_alternates(row.alternates):
                            alt_url = converter.create_url(value=alt)
                            rel = converter.create_relationship(
                                source_id=media_content.id,
                                relationship_type="related-to",
                                target_id=alt_url.id,
                            )
                            bundle_objects.extend([alt_url, rel])
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

                    if rows_in_bundle >= settings.checkfirst.batch_size:
                        try:
                            bundle_json = converter.bundle_serialize(bundle_objects)
                            _send_bundle(bundle_json)
                            report.bundles_sent += 1
                        except Exception as exc:  # noqa: BLE001
                            report.error(SkipReason.BUNDLE_SEND_ERROR)
                            helper.log_error(
                                f"Bundle send failed for {file_key}: {exc}"
                            )
                            raise

                        state = set_file_cursor(state, file_key, last_row_number)
                        save_state_to_helper(helper, state)

                        bundle_objects = []
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

            if rows_yielded == 0:
                helper.log_info(
                    f"No rows yielded for {file_key} (cursor={cursor}). "
                    "Check connector state/cursors and optional guard settings."
                )

            if author is None:
                continue

            if rows_in_bundle > 0 and last_row_number is not None:
                try:
                    bundle_json = converter.bundle_serialize(bundle_objects)
                    _send_bundle(bundle_json)
                    report.bundles_sent += 1
                except Exception as exc:  # noqa: BLE001
                    report.error(SkipReason.BUNDLE_SEND_ERROR)
                    helper.log_error(f"Bundle send failed for {file_key}: {exc}")
                    raise

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
