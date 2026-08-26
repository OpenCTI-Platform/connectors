import os
import time
import traceback
import requests
from bitdefender_import_feed.stixmaker import StixMaker

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

            self.helper.log_info(
                f"{self.helper.connect_name} downloading feed {feedtype}"
            )

            try:
                current = int(time.time())
                seconds = 86400

                if self.state["last_update"][feedtype] != 0:
                    seconds = min(86400, current - self.state["last_update"][feedtype])

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

                self.helper.log_info(
                    f"{self.helper.connect_name} Feed {feedtype} downloaded successfully"
                )

                # Add it into the queue
                self.state["last_update"][feedtype] = current
                self.state["queue"].append(
                    {"feed": feedtype, "file": feedfile, "line": 0}
                )
                self._save_state()

            except Exception as e:
                self.helper.log_error(str(e))
                raise Exception(e) from e

    def import_downloaded_feeds(self):

        while len(self.state["queue"]) > 0:

            entry = self.state["queue"][0]

            self.helper.log_info(
                f"{self.helper.connect_name} importing {entry['feed']} feed"
            )

            processor = StixMaker(
                helper=self.helper,
                feedtype=entry["feed"],
            )

            already_processed_lines = entry["line"]
            processed_lines = 1
            processed_started = time.time()

            try:
                with open(entry["file"], "r", encoding="utf-8") as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        processed_lines += 1

                        if processed_lines < already_processed_lines:
                            continue

                        if line:
                            processor.fromEntry(line)

                        if processed_lines % 500 == 0:
                            entry["line"] = processed_lines - 100  # 100 are in queue
                            self._save_state()
                            dura = time.time() - processed_started
                            self.helper.log_debug(
                                f"Lines: {processed_lines}, lps: {(processed_lines-already_processed_lines)/dura:.1f}"
                            )

                processor.sendFinal()
                os.remove(entry["file"])

            except FileNotFoundError:
                self.helper.log_debug(
                    "Feed file not found (container recreated?) aborting import"
                )

            # Remove the first entry since we're done
            del self.state["queue"][0]
            self._save_state()

    def _run_once(self) -> None:

        # Do we have anything to resume?
        if len(self.state["queue"]) > 0:
            self.state["status"] = "importing"
            self._save_state()
            self.helper.log_debug("Resuming feed import")
            self.import_downloaded_feeds()

        # Download the new feed(s) and save them as local files
        self.helper.log_debug("Downloading feeds")
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
            self.helper.log_debug("Importing downloaded feeds")
            self.import_downloaded_feeds()

        self.state["status"] = "waiting"
        self._save_state()

    def process(self):
        try:
            self._run_once()

        except Exception as e:
            traceback.print_exc()
            self.helper.log_error(str(e))

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
