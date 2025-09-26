"""PGL Yoyo Connector for OpenCTI."""

import re
import uuid
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Any, List, Tuple

import requests
import stix2
from pgl_yoyo.config_loader import ConfigConnector
from pycti import Indicator, OpenCTIConnectorHelper

# Known OpenCTI TLP:WHITE marking-definition UUID
TLP_WHITE_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"


class PGLConnector:
    """
    PGL Yoyo Connector for OpenCTI
    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.conf = config
        # support the config loader which exposes defaults and env overrides
        self.confidence = int(self.conf.confidence_level or 0)
        self.feeds = self.conf.feeds
        self.identity_name = self.conf.identity_name
        self.identity_class = self.conf.identity_class
        self.identity_description = self.conf.identity_description
        self.identity_id_cfg = str(self.conf.identity_id or "").strip()

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "opencti-connector-pgl/1.0"})

    def run(self):
        """Start the connector by scheduling periodic runs."""
        # Use helper.schedule_iso to run process_message periodically
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting PGL connector...",
            {"connector_name": self.helper.connect_name},
        )
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.conf.duration_period,
        )

    def process_message(self) -> None:
        """Main processing executed by the helper scheduler."""
        self.helper.connector_logger.info(
            "[CONNECTOR] PGL connector run started",
            {"connector_name": self.helper.connect_name},
        )
        # Resolve/create a stable Identity for attribution
        identity = self._get_or_build_identity()

        # Pull feeds and collect observables per feed (no caching)
        all_obs: List[Any] = []
        total_lines = 0
        per_feed_counts: List[Tuple[str, int]] = []

        for feed in self.feeds:
            # Fetch without conditional headers
            lines, _ = self._fetch_feed_lines(feed["url"])

            if lines:
                obs = self._build_sco_observables(
                    lines, feed["type"], feed["labels"], identity
                )
                all_obs.extend(obs)
                total_lines += len(lines)
                per_feed_counts.append((feed["name"], len(lines)))
            else:
                per_feed_counts.append((feed["name"], 0))

        self.helper.connector_logger.info(
            f"PGL collected {total_lines} raw entries, into {len(all_obs)} observables"
        )
        for feed_name, count in per_feed_counts:
            self.helper.connector_logger.info(f"  - {feed_name}: {count}")

        if not all_obs:
            self.helper.connector_logger.info("Nothing new to ingest; ending run")
            return

        # Add identity object followed by all observables
        objects: List[Any] = [identity]
        objects.extend(all_obs)

        # Build STIX bundle and send (update=True preserves created timestamps; merges on IDs)
        bundle = stix2.Bundle(
            objects=objects, allow_custom=True, validate=True
        ).serialize()

        # Initiate a new work for this run and send the bundle
        work_id = None
        try:
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, "PGL Yoyo Blocklist Import"
            )
        except Exception:
            work_id = None

        self.helper.send_stix2_bundle(bundle, update=True, work_id=work_id)

        # Persist last_run state
        self._update_last_run()

        # Mark the work as processed when possible
        if work_id is not None:
            try:
                self.helper.api.work.to_processed(
                    work_id, f"{self.helper.connect_name} connector successfully run"
                )
            except Exception:
                pass

        self.helper.connector_logger.info("PGL connector run completed")

    # ---------- helpers ----------

    def _update_last_run(self) -> None:
        """Update the last_run state to current time."""
        try:
            now = datetime.now()
            current_state = self.helper.get_state() or {}
            current_state["last_run"] = now.strftime("%Y-%m-%d %H:%M:%S")
            self.helper.set_state(current_state)
        except Exception:
            pass

    def _fetch_feed_lines(
        self,
        url: str,
    ) -> Tuple[List[str], bool]:
        headers: dict[str, str] = {}

        try:
            resp = self.session.get(url, headers=headers, timeout=30)
        except Exception as e:
            self.helper.connector_logger.info(f"HTTP error for {url}: {e}")
            return [], False

        if resp.status_code == 304:
            return (
                [],
                True,
            )

        if resp.status_code != 200:
            self.helper.connector_logger.info(
                f"Fetch failed ({resp.status_code}) for {url}"
            )
            return [], False

        lines = [ln.strip() for ln in resp.text.splitlines() if ln.strip()]
        return lines, False

    def _get_or_build_identity(self) -> stix2.Identity:
        """
        Build a stable Identity for source attribution.
        We try to keep the same STIX ID across runs (either provided or deterministic).
        """
        if self.identity_id_cfg:
            ident_id = self.identity_id_cfg
        else:
            # Deterministic identity ID: use UUID5 (namespace-based) so the
            # resulting ID is a valid STIX identifier (UUID format) and stable
            # across runs for the same identity name.
            u = uuid.uuid5(uuid.NAMESPACE_DNS, str(self.identity_name))
            ident_id = f"identity--{u}"

        identity = stix2.Identity(
            id=ident_id,
            name=self.identity_name,
            identity_class=self.identity_class,
            description=self.identity_description,
        )
        return identity

    def _is_valid_domain(self, domain: str) -> bool:
        """Basic validation for domain names, including IDN support."""
        # Convert to ASCII for validation (supports IDN)
        try:
            d = domain.strip().rstrip(".").lower()
            # Only encode if non-ASCII characters are present
            if any(ord(c) > 127 for c in d):
                ascii_d = d.encode("idna").decode("ascii")
            else:
                ascii_d = d
        except Exception:
            return False
        if len(ascii_d) > 253:
            return False
        labels = ascii_d.split(".")
        if len(labels) < 2:
            return False
        for label in labels:
            # Accept Unicode word characters and hyphens for IDN labels
            if (
                not 1 <= len(label) <= 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-zA-Z0-9\-]+", label)
            ):
                return False
        return True

    def _build_sco_observables(
        self,
        values: List[str],
        obs_type: str,
        labels: List[str],
        identity: stix2.Identity,
    ) -> List[Any]:
        observables: List[Any] = []

        for val in values:
            try:
                raw = val.strip().lower()
                val = raw.split("#", 1)[0].strip()
                if val:
                    val = val.split()[0]
                else:
                    continue

                # Validate based on observable type
                match obs_type:
                    case "IPv4-Addr":
                        # Handle IPv4 specific logic
                        pt = "ipv4-addr"
                        try:
                            IPv4Address(val)
                        except Exception:
                            self.helper.connector_logger.debug(
                                f"Invalid IPv4 address: {val}"
                            )
                            continue
                    case "Domain-Name":
                        # Handle domain specific logic
                        pt = "domain-name"
                        if not self._is_valid_domain(val):
                            self.helper.connector_logger.debug(
                                f"Invalid domain name: {val}"
                            )
                            continue
                    # Handle other observable types
                    case _:
                        self.helper.connector_logger.warning(
                            f"Unsupported observable type: {obs_type}"
                        )
                        return []

                pattern = f"[{pt}:value = '{val}']"

                sco = stix2.Indicator(
                    id=Indicator.generate_id(pattern),
                    name=f"Indicator for {val}",
                    pattern_type="stix",
                    pattern=pattern,
                    valid_from=datetime.now(timezone.utc),
                    created_by_ref=identity.id,
                    labels=labels,
                    object_marking_refs=[TLP_WHITE_ID],
                )
                observables.append(sco)
            except Exception as e:
                self.helper.connector_logger.info(f"Failed to build SCO for {val}: {e}")

        return observables
