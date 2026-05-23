################################
# OpenCTI Restore Files         #
################################
import datetime
import json
import os
import sys
from pathlib import Path

import yaml
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Splitter, get_config_variable


def ref_extractors(objects):
    ids = []
    for data in objects:
        for key in data.keys():
            if key.startswith("x_") is False:
                if key.endswith("_ref"):
                    ids.append(data[key])
                if key.endswith("_refs"):
                    ids.extend(data[key])
    return set(ids)


def fetch_stix_data(path):
    # ``with open(...)`` guarantees the file descriptor is released even
    # if ``json.loads`` raises on a malformed payload — the previous
    # ``open(...) / read() / close()`` shape leaked the fd on any
    # exception between ``open`` and ``close``, which on a long restore
    # of a corrupt backup tree would slowly exhaust the per-process
    # fd limit. Renamed the parameter from ``file`` to ``path`` so it
    # doesn't shadow the freshly opened file object.
    with open(path, mode="r") as fh:
        file_json = json.load(fh)
    return file_json["objects"]


def date_convert(name):
    return datetime.datetime.strptime(name, "%Y%m%dT%H%M%SZ")


class RestoreFilesConnector:
    def __init__(self, conf_data):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else conf_data
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.direct_creation = get_config_variable(
            "DIRECT_CREATION",
            ["backup", "direct_creation"],
            config,
            default=False,
        )
        self.backup_protocol = get_config_variable(
            "BACKUP_PROTOCOL", ["backup", "protocol"], config
        )
        self.backup_path = get_config_variable(
            "BACKUP_PATH", ["backup", "path"], config
        )

    def find_element(self, backup_files, dir_date, id):
        name = id + ".json"
        candidate_dirs = backup_files.get(name)
        if not candidate_dirs:
            # Missing references are expected — the backup-files connector
            # only writes entities that existed at the time of the snapshot,
            # so an `_ref` pointing at an entity outside the backup window
            # (created later, deleted before the backup ran, scoped out by
            # the upstream stream filter, …) is a normal occurrence. Skip
            # the missing reference silently and let `resolve_missing` move
            # on: callers always check for `None` and a noisy log here
            # would flood the connector logs on every restore.
            return None
        # Multiple run directories may carry the same `<id>.json` —
        # the backup-files connector keys directories on the entity's
        # `created_at` (rounded to a minute), which is supposed to be
        # immutable, but in practice the same id can land in several
        # run-dirs (e.g. when a backup is mirrored from multiple
        # OpenCTI instances, when the `created_at` extension diverges
        # from the bare attribute across stream replays, or simply when
        # operators concatenate two backups under the same
        # `opencti_data` tree). The cache is built while iterating
        # `dirs` in chronological order, so `candidate_dirs` is already
        # sorted ascending. We pick the FIRST snapshot strictly after
        # `dir_date` (the closest later snapshot) so the restore
        # replays the entity's state as it was just after the run
        # directory we are currently restoring — picking the latest
        # snapshot would inject a "from-the-future" version of the
        # entity into the current bundle and force the platform to
        # regress to older versions on subsequent runs. This restores
        # the legacy `os.walk`-based behaviour exactly while keeping
        # the new cache's O(1) miss path on the common
        # single-snapshot case.
        for cand in candidate_dirs:
            if date_convert(cand) > dir_date:
                # ``os.path.join`` rather than string concatenation so a
                # ``backup_path`` with or without a trailing slash both
                # produce a well-formed path on POSIX and Windows.
                return fetch_stix_data(
                    os.path.join(self.backup_path, "opencti_data", cand, name)
                )[0]
        return None

    def resolve_missing(self, backup_files, dir_date, element_ids, data, acc=None):
        # ``acc`` is mutated as the recursive walk discovers missing elements;
        # never use a mutable default value here, otherwise successive top-level
        # invocations would share the same list and cross-run contamination
        # would silently leak elements from one restore directory into another.
        #
        # ``element_ids`` is the same ``set`` instance the main bundle-build
        # loop in ``restore_files`` initialises and passes in: every resolved
        # ``missing_element`` is inserted into ``acc`` AND its id is added to
        # ``element_ids`` so subsequent ``ref not in element_ids`` checks
        # become O(1) set membership instead of a linear scan over the
        # ever-growing ``acc`` list. The previous shape did
        # ``next((x for x in acc if x["id"] == ref), None)`` which made the
        # recursive resolution quadratic in the number of resolved elements
        # on bundles with many shared ancestors.
        if acc is None:
            acc = []
        refs = ref_extractors([data])
        for ref in refs:
            if ref not in element_ids:
                missing_element = self.find_element(backup_files, dir_date, ref)
                if missing_element is not None:
                    acc.insert(0, missing_element)
                    element_ids.add(missing_element["id"])
                    self.resolve_missing(
                        backup_files, dir_date, element_ids, missing_element, acc
                    )

    def restore_files(self):
        stix2_splitter = OpenCTIStix2Splitter()
        state = self.helper.get_state()
        start_directory = (
            state["current"] if state is not None and "current" in state else None
        )
        start_date = (
            date_convert(start_directory) if start_directory is not None else None
        )

        path = os.path.join(self.backup_path, "opencti_data")
        # ``opencti_data`` should only contain run directories named with the
        # date format expected by ``date_convert`` — but skip anything that
        # is not a directory or whose name is not a valid date so a stray
        # file or partially written directory cannot crash the restore.
        valid_entries = []
        for entry in Path(path).iterdir():
            if not entry.is_dir():
                continue
            try:
                date_convert(entry.name)
            except ValueError:
                continue
            valid_entries.append(entry)

        dirs = sorted(valid_entries, key=lambda d: date_convert(d.name))

        # The backup-files connector writes one flat directory per date range
        # under ``opencti_data``, with all entity JSON files at the immediate
        # child level — no nested subdirectories. We exploit that here to
        # build a ``filename → list of run-directory names`` lookup table
        # once so the missing-reference resolution loop below stops
        # re-walking the whole backup tree for every reference. The list
        # shape (rather than a single string) is required because the
        # same ``<id>.json`` can legitimately land in multiple run-dirs
        # (see ``find_element`` for the rationale): collapsing those to
        # a single entry would silently regress restored state when an
        # entity changed across snapshots. ``dirs`` is iterated in
        # chronological order so each list is sorted ascending without
        # an explicit sort step.
        # Resume mode: the main restore loop below skips every run-dir
        # whose date is ``<= start_date`` (the timestamp of the last
        # successfully restored directory), so ``find_element`` is only
        # ever called with a ``dir_date > start_date``. ``find_element``
        # in turn only ever returns snapshots strictly later than
        # ``dir_date``, which means snapshots from directories at or
        # before ``start_date`` can never be a valid resolution target.
        # Skipping them here avoids ``os.scandir``-ing the entire
        # pre-``start_date`` history on every resume — on long-lived
        # backups (months of run-dirs) that is the difference between
        # a sub-second cache build and a multi-minute one. ``dirs`` is
        # iterated in chronological order so each cache list is still
        # sorted ascending without an explicit sort step.
        if start_date is not None:
            cache_dirs = [d for d in dirs if date_convert(d.name) > start_date]
        else:
            cache_dirs = dirs
        self.helper.log_info(
            "Building files map cache (could take a while) — indexing "
            + str(len(cache_dirs))
            + " of "
            + str(len(dirs))
            + " run directories"
            + (
                " (skipping "
                + str(len(dirs) - len(cache_dirs))
                + " at or before resume cursor "
                + start_directory
                + ")"
                if start_date is not None
                else ""
            )
        )
        cache_start_time = datetime.datetime.now()
        backup_files = dict()
        snapshot_count = 0
        for entry in cache_dirs:
            with os.scandir(entry) as it:
                for file in it:
                    # Filter to ``*.json`` files: ``find_element`` only ever
                    # looks up ``<id>.json`` keys, so caching anything else
                    # (subdirectories, symlinks-to-dirs, sidecar files like
                    # ``manifest.txt`` / ``.gitkeep`` / temporary writes) is
                    # pure waste — it inflates memory and slows the cache
                    # build on large backups without ever producing a hit.
                    # ``file.is_file()`` also guards against symlinks-to-dirs
                    # that would otherwise crash ``fetch_stix_data`` further
                    # down if a non-JSON entry somehow matched a lookup.
                    if file.is_file() and file.name.endswith(".json"):
                        backup_files.setdefault(file.name, []).append(entry.name)
                        snapshot_count += 1
        cache_duration = (datetime.datetime.now() - cache_start_time).total_seconds()
        self.helper.log_info(
            "Files map cache built in "
            + str(cache_duration)
            + "s ("
            + str(len(backup_files))
            + " unique files / "
            + str(snapshot_count)
            + " snapshots indexed across "
            + str(len(cache_dirs))
            + " directories)"
        )

        for entry in dirs:
            friendly_name = "Restore run directory @ " + entry.name
            self.helper.log_info(friendly_name)
            dir_date = date_convert(entry.name)
            if start_date is not None and dir_date <= start_date:
                continue
            # 00 - Create a bundle for the directory
            files_data = []
            element_ids = []
            # 01 - build all _ref / _refs contained in the bundle.
            #
            # ``os.scandir`` returns an iterator that holds an OS-level
            # directory handle (``DIR*`` on POSIX, ``HANDLE`` on Windows);
            # wrap it in a ``with`` block so the handle is released as
            # soon as we are done iterating, matching the cache-build
            # site above and avoiding a per-run-dir handle leak on long
            # restore runs. ``file.is_file()`` keeps subdirectories and
            # symlinks-to-dirs out of the bundle so ``fetch_stix_data``
            # never tries to ``open()`` something that is not a regular
            # file.
            element_refs = []
            with os.scandir(entry) as it:
                for file in it:
                    if file.is_file():
                        # Pass the explicit ``str`` path rather than the
                        # ``DirEntry`` itself so ``fetch_stix_data``'s
                        # ``open(path, mode="r")`` does not rely on the
                        # implicit ``os.PathLike`` protocol — keeps the
                        # call site symmetric with the ``find_element``
                        # path (which already passes a string built
                        # via ``os.path.join``).
                        objects = fetch_stix_data(file.path)
                        object_ids = set(map(lambda x: x["id"], objects))
                        element_refs.extend(ref_extractors(objects))
                        files_data.extend(objects)
                        element_ids.extend(object_ids)
            # Ensure the bundle is consistent (include meta elements)
            # 02 - Scan bundle to detect missing elements
            acc = []
            ids = set(element_ids)
            refs = set(element_refs)
            start_time = datetime.datetime.now()
            for ref in refs:
                if ref not in ids:
                    # 03 - If missing, scan the other dir/files to find the elements
                    missing_element = self.find_element(backup_files, dir_date, ref)
                    if missing_element is not None:
                        acc.insert(0, missing_element)
                        # Dedup against ``ids`` so any other ref in this same
                        # bundle that points at the same missing entity hits
                        # the O(1) ``ref not in ids`` early exit on the next
                        # loop iteration instead of going through the slow
                        # ``find_element`` + recursive ``resolve_missing``
                        # path again. ``ids`` is also the same set instance
                        # passed into ``resolve_missing`` below, so the
                        # recursive walk shares the same dedup state.
                        ids.add(missing_element["id"])
                        # 04 - Restart the process to handle recursive resolution
                        self.resolve_missing(
                            backup_files, dir_date, ids, missing_element, acc
                        )
            # 05 - Add elements to the bundle
            objects_with_missing = acc + files_data
            stop_time = datetime.datetime.now()
            # Past tense + explicit ``s`` suffix so the line is
            # unambiguous in production logs: the work is already done
            # by the time we log it, and a raw float without a unit can
            # be misread as milliseconds at a glance on busy log views.
            self.helper.log_info(
                "Handled missing reference resolution in "
                + str((stop_time - start_time).total_seconds())
                + "s ("
                + str(len(objects_with_missing))
                + " objects)"
            )
            if len(objects_with_missing) > 0:
                # Create the work
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                # 06 - Send the bundle to the worker queue
                stix_bundle = {
                    "type": "bundle",
                    "objects": objects_with_missing,
                }
                if self.direct_creation:
                    # Bundle must be split for reordering
                    bundles = stix2_splitter.split_bundle(stix_bundle, False)
                    self.helper.log_info(
                        "restore dir "
                        + entry.name
                        + " with "
                        + str(len(bundles))
                        + " bundles (direct creation)"
                    )
                    for bundle in bundles:
                        self.helper.api.stix2.import_bundle_from_json(
                            json.dumps(bundle), True
                        )
                    # 06 - Save the state
                    self.helper.set_state({"current": entry.name})
                else:
                    self.helper.log_info("restore dir (worker bundles):" + entry.name)
                    self.helper.send_stix2_bundle(
                        json.dumps(stix_bundle), work_id=work_id
                    )
                    message = "Restore dir run, storing last_run as {0}".format(
                        entry.name
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    # 06 - Save the state
                    self.helper.set_state({"current": entry.name})
        self.helper.log_info("restore run completed")

    def start(self):
        # Check if the directory exists
        backup_root = os.path.join(self.backup_path, "opencti_data")
        if not os.path.exists(backup_root):
            raise ValueError("Backup path does not exist - " + backup_root)
        self.restore_files()


if __name__ == "__main__":
    json_conf = sys.argv[1] if len(sys.argv) > 1 else None
    conf = json.loads(json_conf) if json_conf is not None else {}
    RestoreFilesInstance = RestoreFilesConnector(conf)
    RestoreFilesInstance.start()
