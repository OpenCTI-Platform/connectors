import os
import time
import traceback

import requests
from src.bitdefender_import_feed.stixmaker import StixMaker


class BitdefenderFeedConnector:
    def __init__(self, config, helper) -> None:
        self.config = config
        self.helper = helper
        self.creator_identity = None
        self.state = self.helper.get_state() or {
            "last_update": {"file": 0, "ip": 0, "web": 0},
            "queue": [],
        }

    def _save_state(self):
        self.helper.set_state(self.state)

    def download_feeds(self) -> None:

        for feedtype in self.config.bitdefender.feeds:

            self.helper.connector_logger.info(
                f"{self.helper.connect_name} downloading feed {feedtype}"
            )

            try:
                current = int(time.time())
                seconds = self.config.bitdefender.max_lookback_interval

                if self.state["last_update"][feedtype] != 0:
                    # Provider API accepts at most 24 hours of history. Warn about
                    # any unrecoverable gap rather than silently truncating it.
                    elapsed = current - self.state["last_update"][feedtype]
                    if elapsed > self.config.bitdefender.max_lookback_interval:
                        self.helper.connector_logger.warning(
                            f"Feed {feedtype}: {elapsed - self.config.bitdefender.max_lookback_interval} seconds outside "
                            "the look-back window"
                        )
                    seconds = min(
                        self.config.bitdefender.max_lookback_interval, elapsed
                    )

                # Download the feed using Bitdefender TI API
                headers = {
                    "auth-token": self.config.bitdefender.api_key.get_secret_value(),
                    "Accept-Encoding": "identity",
                }

                params = {
                    "feed_name": f"{feedtype}-feed",
                    "last_seconds": seconds,
                    "min_confidence": self.config.bitdefender.min_confidence,
                    "min_severity": self.config.bitdefender.min_severity,
                    "include_revoked": self.config.bitdefender.include_revoked,
                    "exclude_related_indicators": str(
                        self.config.bitdefender.exclude_related_indicators
                    ).lower(),
                }

                if feedtype == "file":
                    params["exclude_similar_files"] = str(
                        self.config.bitdefender.exclude_similar_files
                    ).lower()
                    params["include_suspicious_entries"] = (
                        self.config.bitdefender.include_suspicious
                    )

                r = requests.get(
                    "https://feeds.ti.bitdefender.com/reputation",
                    params=params,
                    headers=headers,
                    timeout=self.config.bitdefender.http_timeout_seconds,
                    verify=self.config.bitdefender.verify_tls,
                    stream=True,
                )

                r.raise_for_status()

                # Save the feed into a file
                feedfile = feedtype + ".json"

                with open(feedfile, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

                self.helper.connector_logger.info(
                    f"{self.helper.connect_name} Feed {feedtype} downloaded successfully"
                )

                # Do not advance the watermark until the downloaded file has been
                # imported; container recreation can otherwise permanently lose it.
                self.state["queue"].append(
                    {"feed": feedtype, "file": feedfile, "line": 0, "until": current}
                )
                self._save_state()

            except Exception as e:
                self.helper.connector_logger.error(str(e))
                raise Exception(e) from e

    def import_downloaded_feeds(self):

        while len(self.state["queue"]) > 0:

            entry = self.state["queue"][0]

            self.helper.connector_logger.info(
                f"{self.helper.connect_name} importing {entry['feed']} feed"
            )

            processor = StixMaker(
                config=self.config,
                helper=self.helper,
                feedtype=entry["feed"],
            )

            already_processed_lines = entry["line"]
            processed_started = time.time()

            try:
                with open(entry["file"], "r", encoding="utf-8") as f:
                    for line_number, raw_line in enumerate(f, 1):
                        if line_number <= entry["line"]:
                            continue

                        line = raw_line.strip()
                        if not line:
                            continue

                        try:
                            bundle_sent = processor.fromEntry(line)
                        except Exception as e:
                            self.helper.connector_logger.error(
                                f"Feed {entry['feed']}, line {line_number}: {e}"
                            )
                            continue

                        if line_number % 500 == 0:
                            dura = max(time.time() - processed_started, 0.001)
                            self.helper.connector_logger.debug(
                                f"Lines: {line_number}, lps: {(line_number-already_processed_lines)/dura:.1f}"
                            )

                        if bundle_sent:
                            entry["line"] = line_number
                            self._save_state()

                processor.sendFinal()
                os.remove(entry["file"])
                # Support persisted queue entries created before the `until` field.
                self.state["last_update"][entry["feed"]] = entry.get(
                    "until", self.state["last_update"][entry["feed"]]
                )

            except FileNotFoundError:
                self.helper.connector_logger.error(
                    "Feed file should exist but not found - container recreated? aborting import"
                )
                processor.sendError("Downloaded feed file is missing")

            except Exception as e:
                processor.sendError(str(e))
                # Keep the current queue entry for the next run.
                raise

            # Remove the first entry since we're done
            del self.state["queue"][0]
            self._save_state()

    def _run_once(self) -> None:

        # Do we have anything to resume?
        if len(self.state["queue"]) > 0:
            self.state["status"] = "importing"
            self._save_state()
            self.helper.connector_logger.debug("Resuming feed import")
            self.import_downloaded_feeds()

        # Download the new feed(s) and save them as local files
        self.helper.connector_logger.debug("Downloading feeds")
        self.state["status"] = "downloading"
        self._save_state()

        try:
            self.download_feeds()
        except Exception as e:
            self.state["status"] = "error downloading feeds: " + str(e)
            self._save_state()

            # If no feeds were downloaded, we return.
            # Otherwise we import those we downloaded.
            if len(self.state["queue"]) == 0:
                return

        # If the feeds are downloaded, import them
        if len(self.state["queue"]) > 0:
            self.state["status"] = "importing"
            self._save_state()
            self.helper.connector_logger.debug("Importing downloaded feeds")
            self.import_downloaded_feeds()

        self.state["status"] = "waiting"
        self._save_state()

    def process(self):
        try:
            self._run_once()

        except Exception as e:
            traceback.print_exc()
            self.helper.connector_logger.error(str(e))

        self.state["last_run"] = int(time.time())
        self._save_state()

    def run(self) -> None:
        self.helper.connector_logger.info(
            "Starting Bitdefender Feed Import connector..."
        )
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
