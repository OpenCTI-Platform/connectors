"""CrowdStrike API HTTP Event Collector.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from gzip import open as gzip_open
from logging import Logger, getLogger, FileHandler
from time import sleep
from typing import Dict, Union, List, Iterable, Any
from requests import Response, Session
from requests.exceptions import (
    ReadTimeout,
    Timeout,
    InvalidURL,
    SSLError,
    ConnectionError as RequestConnectionError
    )
from ._ingest_config import IngestConfig
from ._ingest_payload import IngestPayload
from ._session_manager import SessionManager
from .._enum import IngestFormat
from .._log import LogFacility
from .._util import sanitize_dictionary
from .._version import _VERSION, _HEC_VERSION


class HEC:  # pylint: disable=R0902,R0904
    """CrowdStrike Falcon Next-Gen SIEM HTTP Event Collector.

    FalconPy                       ⣠⣴⣾⣿⣿⣿⣿⣿⣿⣶⣤⣄
                                 ⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄
    ██╗  ██╗███████╗ ██████╗   ⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣆⠉⠉⢉⣿⣿⣿⣷⣦⣄⡀
    ██║  ██║██╔════╝██╔════╝  ⠚⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
    ███████║█████╗  ██║       ⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠿⠿⣿⡇
    ██╔══██║██╔══╝  ██║      ⢀⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⠀⠀⠀⠈⠃
    ██║  ██║███████╗╚██████╗ ⠸⠁⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏
    ╚═╝  ╚═╝╚══════╝ ╚═════╝   ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏
                                ⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⠁
     for CrowdStrike Falcon     ⠹⣿⣿⡇⠈⠻⣿⣿⣿⣿
         Next-Gen SIEM           ⠈⠻⡇⠀⠀⠈⠙⠿⣿
    """

    _last_status: int = None
    _last_message: str = None
    _log_facility: LogFacility = LogFacility()
    _session_manager: SessionManager = None

    def __init__(self,
                 api_key: str,
                 api_url_key: str,
                 debug: bool = False,
                 **kwargs
                 ):
        """Construct an instance of the HTTP event collector.

        Keyword arguments
        ----
        api_key: (string) [required]
            NGSIEM API key.
        api_url_key: (string) [required]
            NGSIEM URL key, used to craft the target URL.
        ingest_format: (string)
            Ingest format. Defaults to "json".
                Allowed values = "json", "yaml", "xml", or "csv"
        ingest_region: (string)
            Ingest region, used to craft the target URL. Defaults to "us1".
                Allowed values = "us1", "us2", "eu1", or "usgov1"
        ingest_timeout: (integer)
            Request timeout in seconds for ingest submissions. Defaults to 5.
        ingest_timeunit: (string)
            Ingest timestamp format. Defaults to "nanoseconds".
                Allowed values = "nanoseconds", "milliseconds", or "seconds"
        raw_ingest: (boolean)
            Use the NGSIEM raw ingestion endpoint. Defaults to False.
        retry_count: (integer)
            Number of request retries before erroring on the thread. Defaults to 3.
        thread_count: (integer)
            Number of threads to use for asynchronous processing.
            Defaults to CPU count * 2 or 50, whichever is smaller.
        debug: (boolean)
            Enable debugging. Defaults to False.
        sanitize_log: (boolean)
            Sanitize the bearer token from API logs. Defaults to True.
        """
        self.ingest_config = IngestConfig(api_key, api_url_key, **kwargs)
        self.session_manager = SessionManager(kwargs.get("thread_count", None),
                                              kwargs.get("retry_count", 3)
                                              )
        if debug:
            self.log_facility = LogFacility(getLogger(__name__),
                                            None,
                                            kwargs.get("sanitize_log", True)
                                            )
            if self.log.root.hasHandlers():
                for handler in self.log.root.handlers:
                    if isinstance(handler, FileHandler):
                        self.file_log = 2
            self.log_startup()

    def __enter__(self):
        """Allow for entry as a context manager."""
        return self

    def __exit__(self, *args):
        """Context manager exit."""
        self.log_activity(args[1])

    def format_event(self,
                     evt: Union[Dict[str, Any], IngestPayload]
                     ) -> Union[Dict[str, Any], IngestPayload]:
        """Format the event to include missing keys."""
        returned = None
        if isinstance(evt, IngestPayload):
            evt.timeunit = self.ingest_timeunit
            returned = evt.to_json(self.raw_ingest)
        else:
            returned = IngestPayload(**evt, timeunit=self.ingest_timeunit).to_json(self.raw_ingest)

        return returned

    def slice_raw_data(self, data: str) -> List[str]:
        """Slice raw data into manageable chunks."""
        max_chunk_size = 10_240_000
        data_length = len(data)
        created = []
        start = 0
        total = 0
        while start < data_length:
            end = min(start + max_chunk_size, data_length)
            if end < data_length and "\n" in data[start:end]:
                split_index = data.rfind("\n", start, end)
                if split_index != -1:
                    end = split_index + 1
            batch_total = len(data[start:end].split("\n")) - 1
            self.log_activity(f"Created batch of {batch_total} records")
            total += batch_total
            created.append({"data": data[start:end], "count": batch_total})
            start = end
        self.log_activity(f"{total} records processed into {len(created)} batches")

        return created

    @staticmethod
    def detect_gzip(filename) -> bool:
        """Detect if a provided raw file is gzip compressed by checking the magic number."""
        try:
            with open(filename, 'rb') as test_f:
                return test_f.read(2) == b'\x1f\x8b'
        except (FileNotFoundError, OSError) as not_found:
            raise SystemExit("Specified raw file not found.") from not_found

    def send_event_file(self, event_file: str) -> int:
        """Upload a file of events, this method leverages the raw endpoint."""
        self.log_activity(f"EVENT FILE: {event_file}")
        if self.detect_gzip(event_file):
            with gzip_open(event_file, "rt") as gzip_file:
                batches = self.slice_raw_data("".join(list(gzip_file.readlines())))
        else:
            with open(event_file, "r", encoding="utf-8") as ingest_file:
                batches = self.slice_raw_data(ingest_file.read())
        with ThreadPoolExecutor(max_workers=self.thread_count,
                                thread_name_prefix="thread"
                                ) as executor:
            for batch in batches:
                self.log_activity(f"Submitting batch of {batch['count']} records")
            futures = {executor.submit(self._retry_event, batch["data"]) for batch in batches}
            for future in futures:
                if not future.result():
                    self.log_activity([f"STATUS CODE: {self.last_status}",
                                       f"RESPONSE: {self.last_message}"
                                       ])
                else:
                    self.track_result(future.result().status_code, future.result().json())
                    self.log_activity([f"STATUS CODE: {future.result().status_code}",
                                       f"RESPONSE HEADERS: {future.result().headers}",
                                       f"RESPONSE: {future.result().json()}"
                                       ])

        return self.last_status

    def _retry_event(self, evt: Union[Dict[str, Any], str]) -> Response:
        response = None
        error_condition = None
        ingest_to = self.ingest_url
        raw = None
        if self.raw_ingest:
            ingest_to = self.raw_ingest_url
            raw = evt
            evt = None
        for transmission_count in range(1, self.retry_count+1):
            try:
                response = next(self.session_manager).post(ingest_to,
                                                           headers=self.hec_headers,
                                                           json=evt,
                                                           verify=True,
                                                           timeout=self.ingest_timeout,
                                                           data=raw
                                                           )
                break

            except (InvalidURL, SSLError) as request_error:
                self.log_activity(f"REQUEST FAILURE: Retry #{transmission_count}")
                self.log_activity(f"FAILURE REASON: {request_error}")
                error_condition = request_error
                sleep(transmission_count*2)

            except (ReadTimeout, Timeout, TimeoutError, ConnectionError, RequestConnectionError):
                error_condition = "TIMEOUT"
                self.log_activity(f"REQUEST TIMEOUT: Retry #{transmission_count}")
                sleep(transmission_count*2)

        if transmission_count == self.retry_count:
            if error_condition == "TIMEOUT":
                self.log_activity(f"REQUEST TIMEOUT: {evt if evt else 'Raw file import'}")
                self.track_result(500, "TIMEOUT ERROR: Check connectivity or increase timeout")
            else:
                self.log_activity(f"REQUEST FAILED: {evt if evt else 'Raw file import'}")
                self.log_activity(f"FAILURE REASON: {error_condition}")
                self.track_result(500, f"REQUEST FAILURE: {error_condition}")

        return response

    def send_event(self, event: Union[Dict[str, Any], IngestPayload]) -> int:
        """Send an event and return the status code."""
        event = self.format_event(event)
        header_log = self.hec_headers
        if self.sanitize_log:
            header_log = sanitize_dictionary(self.hec_headers)
        self.log_activity([f"REQUEST HEADERS: {header_log}", f"EVENT PROCESSED: {event}"])
        response = self._retry_event(event)
        if response:
            self.track_result(response.status_code, response.json())
            self.log_activity([f"RESPONSE CODE: {self.last_status}",
                               f"RESPONSE HEADERS: {response.headers}",
                               f"RESPONSE TEXT: {self.last_message}"
                               ])

        return self.last_status

    def process_list_with_progress(self,
                                   events: List[Union[Dict[str, Any], IngestPayload]]
                                   ) -> Iterable[int]:
        """Asynchronously send a list of events while showing a progress indicator."""
        with ThreadPoolExecutor(max_workers=self.thread_count,
                                thread_name_prefix="thread"
                                ) as executor:
            futures = executor.map(self.send_event, events)
            success_count = 0
            for future in futures:
                if future == 200:
                    success_count += 1
                    self.log_activity(f"LIST PROGRESS: Event {success_count} of {len(events)} processed.")
                yield success_count

    def process_list(self, events: List[Union[Dict[str, Any], IngestPayload]]) -> int:
        """Asynchronously send a list of events."""
        with ThreadPoolExecutor(max_workers=self.thread_count,
                                thread_name_prefix="thread"
                                ) as executor:
            futures = executor.map(self.send_event, events)
            success_count = 0
            for future in futures:
                if future == 200:
                    success_count += 1
                    self.log_activity(f"LIST PROGRESS: Event {success_count} of {len(events)} processed.")

        return success_count

    def send_event_list(self,
                        event_list: List[Union[Dict[str, Any], IngestPayload]],
                        show_progress: bool = False
                        ) -> Union[int, Iterable[int]]:
        """Asynchronously send a list of events, returning the number of successful submissions."""
        self.log_activity("EVENT LIST: BEGIN PROCESSING")
        if show_progress:
            returned = self.process_list_with_progress(event_list)
        else:
            returned = self.process_list(event_list)
            self.log_activity(f"EVENT LIST: Processing of {len(event_list)} "
                              f"events completed with {returned} successes"
                              )

        return returned

    def test_connection(self) -> bool:
        """Test the connection and return a boolean indicating success or failure."""
        returned = False
        self.log_activity("CONNECTION TEST: BEGIN")
        test_payload = {"host": "connection_test", "test": "connection"}
        if self.send_event(test_payload) == 200:
            self.log_activity("CONNECTION TEST: SUCCESS")
            returned = True
        else:
            self.log_activity("CONNECTION TEST: FAILED")

        return returned

    def track_result(self, code: int, msg: str):
        """Update the last_status and last_message fields."""
        self.last_status = code
        self.last_message = msg

    def log_activity(self, msg: Union[str, List[str]], logo: bool = False):
        """Update the debug log with the provided message(s)."""
        if msg and self.log:
            if isinstance(msg, list):
                for line in msg:
                    if logo:
                        bracket = " " if self.file_log else "┃"
                        self.log.debug("%s  %s %s %s", bracket, line, " "*(51-len(line)), bracket)
                    else:
                        self.log.debug(line)
            else:
                self.log.debug(msg)

    def log_startup(self):
        """Log the collector startup configuration."""
        self.log_activity(f"{'━' if self.file_log else '┏'}"
                          f"{'━'*(55+self.file_log)}{'━' if self.file_log else '┓'}",
                          logo=True
                          )
        self.log_activity(self.__doc__.split("\n")[2:-1], logo=True)
        self.log_activity(f"{'━' if self.file_log else '┗'}"
                          f"{'━'*(55+self.file_log)}"
                          f"{'━' if self.file_log else '┛'}",
                          logo=True
                          )
        self.log_activity(["HTTP EVENT COLLECTOR: Instance created",
                           f"VERSION: FalconPy {_VERSION} / HEC {_HEC_VERSION}",
                           "START TIME: "
                           f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}",
                           f"INGEST FORMAT: {self.ingest_format_name}",
                           f"INGEST TIME UNIT: {self.ingest_timeunit.title()}"
                           ])
        ingest_to = self.ingest_url
        if self.raw_ingest:
            ingest_to = self.raw_ingest_url
        self.log_activity([f"CONNECTOR URL: {ingest_to}",
                           f"RAW INGEST: {'Enabled' if self.raw_ingest else 'Disabled'}",
                           f"REQUEST TIMEOUT: {self.ingest_config.ingest_timeout} seconds",
                           f"REQUEST RETRY COUNT: {self.retry_count} attempts",
                           f"ASYNC SESSION COUNT: {len(self.session_manager)}",
                           f"ASYNC THREAD COUNT: {self.thread_count} threads"
                           ])

    #  _______ _     _ _______ _______ ______         _______
    #  |  |  | |     |    |    |_____| |_____] |      |______
    #  |  |  | |_____|    |    |     | |_____] |_____ |______
    #
    #   _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    #  |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    #  |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    # These properties are set when an instance of the collector is created and can modified.
    #
    # _ _  _ ____ ____ ____ ___    ____ ____ _  _ ____ _ ____
    # | |\ | | __ |___ [__   |     |    |  | |\ | |___ | | __
    # | | \| |__] |___ ___]  |     |___ |__| | \| |    | |__]
    #
    # Ingest configuration properties.
    #
    @property
    def ingest_config(self) -> IngestConfig:
        """Return the ingest configuration object."""
        return self._ingest_config

    @ingest_config.setter
    def ingest_config(self, value: IngestConfig):
        """Set the ignest configuration object."""
        self._ingest_config = value

    @property
    def ingest_key(self) -> str:
        """API ingest key."""
        return self.ingest_config.ingest_key

    @ingest_key.setter
    def ingest_key(self, value: str):
        """Set the API ingest key value."""
        self.ingest_config.ingest_key = value

    @property
    def ingest_url_key(self) -> str:
        """API ingest URL key."""
        return self.ingest_config.ingest_url_key

    @ingest_url_key.setter
    def ingest_url_key(self, value: str):
        """Set the API ingest URL key value."""
        self.ingest_config.ingest_url_key = value

    @property
    def ingest_format(self) -> str:
        """API ingest format."""
        return self.ingest_config.ingest_format

    @ingest_format.setter
    def ingest_format(self, value: str):
        """Set the API ingest key value."""
        self.ingest_config.ingest_format = value

    @property
    def ingest_timeout(self) -> str:
        """API ingest timeout."""
        return self.ingest_config.ingest_timeout

    @ingest_timeout.setter
    def ingest_timeout(self, value: str):
        """Set the API ingest timeout value."""
        self.ingest_config.ingest_timeout = value

    @property
    def ingest_timeunit(self) -> str:
        """API ingest timeunit."""
        return self.ingest_config.ingest_timeunit

    @ingest_timeunit.setter
    def ingest_timeunit(self, value: str):
        """Set the API ingest timeunit value."""
        self.ingest_config.ingest_timeunit = value

    @property
    def ingest_base_url(self) -> str:
        """API ingest base URL."""
        return self.ingest_config.ingest_base_url

    @ingest_base_url.setter
    def ingest_base_url(self, value: str):
        """Set the API ingest base URL value."""
        self.ingest_config.ingest_base_url = value

    @property
    def raw_ingest(self) -> bool:
        """Return the current raw ingest mode."""
        return self.ingest_config.raw_ingest

    @raw_ingest.setter
    def raw_ingest(self, value: bool):
        """Set the raw ingest mode."""
        self.ingest_config.raw_ingest = value

    # ____ ____ _    _    ____ ____ ___ ____ ____
    # |    |  | |    |    |___ |     |  |  | |__/
    # |___ |__| |___ |___ |___ |___  |  |__| |  \
    #
    # Collector properties.
    #
    @property
    def last_status(self) -> int:
        """Last API response status code."""
        return self._last_status

    @last_status.setter
    def last_status(self, value: int):
        """Set the API response status code."""
        self._last_status = value

    @property
    def last_message(self) -> str:
        """Last API response message."""
        return self._last_message

    @last_message.setter
    def last_message(self, value: str):
        """Set the API response message."""
        self._last_message = value

    # _    ____ ____ ____ _ _  _ ____
    # |    |  | | __ | __ | |\ | | __
    # |___ |__| |__] |__] | | \| |__]
    #
    # Debug log properties.
    #
    @property
    def log_facility(self) -> LogFacility:
        """Debug logging facility."""
        return self._log_facility

    @log_facility.setter
    def log_facility(self, value: LogFacility):
        """Set the debug logging facility."""
        self._log_facility = value

    @property
    def sanitize_log(self) -> Logger:
        """Flag to indicate if log sanitization is enabled."""
        return self.log_facility.sanitize_log

    @sanitize_log.setter
    def sanitize_log(self, value: Logger):
        """Enable or disable log sanitization."""
        self.log_facility.sanitize_log = value

    @property
    def file_log(self) -> int:
        """Integer flag indicating if the log is writing to a file."""
        return self.log_facility.file_log

    @file_log.setter
    def file_log(self, value: int):
        """Set the file_log flag."""
        self.log_facility.file_log = value

    # Immutable log property
    @property
    def log(self) -> Logger:
        """Debug logger."""
        return self.log_facility.log

    # ____ ____ ____ ____ _ ____ _  _    _  _ ____ _  _ ____ ____ ____ _  _ ____ _  _ ___
    # [__  |___ [__  [__  | |  | |\ |    |\/| |__| |\ | |__| | __ |___ |\/| |___ |\ |  |
    # ___] |___ ___] ___] | |__| | \|    |  | |  | | \| |  | |__] |___ |  | |___ | \|  |
    #
    # HTTP session management properties.
    #
    @property
    def session_manager(self) -> SessionManager:
        """Manager to handle sessions used for asynchronous processing."""
        return self._session_manager

    @session_manager.setter
    def session_manager(self, value: SessionManager):
        """Set the session manager."""
        self._session_manager = value

    @property
    def sessions(self) -> List[Session]:
        """Return the sessions list."""
        return self.session_manager.sessions

    @sessions.setter
    def sessions(self, value: List[Session]):
        """Set the contents of the session list."""
        self.session_manager.sessions = value

    @property
    def retry_count(self) -> int:
        """HTTP request retry count."""
        return self.session_manager.retry_count

    @retry_count.setter
    def retry_count(self, value: int):
        """Set the HTTP request retry count."""
        self.session_manager.retry_count = value

    @property
    def thread_count(self) -> int:
        """Return the default thread count."""
        return self.session_manager.thread_count

    @thread_count.setter
    def thread_count(self, value: int):
        """Set the default thread count."""
        self.session_manager.thread_count = value

    #  _____ _______ _______ _     _ _______ _______ ______         _______
    #    |   |  |  | |  |  | |     |    |    |_____| |_____] |      |______
    #  __|__ |  |  | |  |  | |_____|    |    |     | |_____] |_____ |______
    #
    #   _____   ______  _____   _____  _______  ______ _______ _____ _______ _______
    #  |_____] |_____/ |     | |_____] |______ |_____/    |      |   |______ |______
    #  |       |    \_ |_____| |       |______ |    \_    |    __|__ |______ ______|
    #
    # These properties cannot be changed.
    #
    @property
    def ingest_format_name(self) -> str:
        """Return the name of the ingest format."""
        returned = None
        for format_type in IngestFormat:
            if format_type.value == self.ingest_format:
                returned = format_type.name

        return returned

    @property
    def ingest_url(self) -> str:
        """Ingestion URL calculated from API url key and base URL."""
        return f"https://{self.ingest_url_key}.{self.ingest_base_url}/services/collector"

    @property
    def raw_ingest_url(self) -> str:
        """Raw ingestion URL calculated from API url key and base URL."""
        return f"{self.ingest_url}/raw"

    @property
    def hec_headers(self) -> Dict[str, str]:
        """Authorization headers."""
        return {
            "Authorization": f"Bearer {self.ingest_key}",
            "Content-Type": self.ingest_format
            }
