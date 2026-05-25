import ipaddress
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Module-level email regex.
#
# Compiled once at import time so the per-signal scan in
# :meth:`DataImporter._extract_observables_from_http_headers` does not
# re-compile the same pattern on every alert. On a cycle that hits the
# per-cycle cap (``DataDogClient._MAX_SIGNALS_PER_CYCLE`` = 10,000)
# the previous shape was paying one ``re.compile`` per signal on top of
# a full ``json.dumps(raw_signal)`` serialization — both wasted CPU and
# allocated large temporary strings. The scan is now applied directly
# to each string leaf of the signal tree (see
# :meth:`DataImporter._find_values`) rather than the serialized blob.
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


class DataImporter:
    """Handles data import processing and validation"""

    def __init__(self, helper):
        """
        Initialize importer

        Args:
            helper: OpenCTI connector helper instance
        """
        self.helper = helper

    def process_datadog_data(
        self, import_data: list[dict[str, Any]], **kwargs
    ) -> dict[str, Any]:
        """
        Process DataDog alerts data

        Args:
            import_data: List of data dictionaries with type and data
            **kwargs: Processing options

        Returns:
            Processed data ready for STIX conversion
        """
        try:
            processed_items = []
            # ``per_item_errors`` counts the alerts that
            # :meth:`_process_datadog_alert` returned ``None`` for —
            # i.e. the per-alert ``try`` swallowed a malformed signal
            # and logged it. Without this counter every per-alert
            # failure would land in the caller as
            # ``processed_items=[]`` / ``errors=0``, which the cycle
            # gate in ``connector.py`` reads as "nothing to do" and
            # advances the state cursor past the failed window —
            # silently dropping the data forever. The counter is
            # surfaced via ``errors`` so the cycle is marked red and
            # the cursor is held at the previous value (see the
            # ``object_errors > 0`` branches in ``_import_data``).
            per_item_errors = 0

            for data_source in import_data:
                data_type = data_source.get("type")
                data_items = data_source.get("data", [])

                self.helper.log_info(f"Processing {len(data_items)} {data_type}")

                if data_type == "alerts":
                    for alert in data_items:
                        processed_alert = self._process_datadog_alert(alert, **kwargs)
                        if processed_alert:
                            processed_items.append(processed_alert)
                        else:
                            per_item_errors += 1

            return {
                "processed_items": processed_items,
                "total_processed": len(processed_items),
                "timestamp": datetime.now(UTC).isoformat(),
                "errors": per_item_errors,
            }

        except Exception as e:
            # ``errors=1`` MUST be surfaced here — without it, an
            # importer-level failure (e.g. a malformed signal that
            # short-circuits the whole loop) is indistinguishable from
            # a clean "no alerts to process" cycle in the caller's
            # ``object_errors == 0`` gate, advances the state cursor
            # past the failed window, and silently drops the data.
            # ``connector.py::_import_data`` reads this flag and folds
            # it into the cycle's ``errors`` count so the OpenCTI Work
            # is marked red instead of green-on-failure.
            self.helper.log_error(f"Error processing DataDog data: {str(e)}")
            return {"processed_items": [], "total_processed": 0, "errors": 1}

    def _process_datadog_alert(
        self, alert: dict[str, Any], **kwargs
    ) -> dict[str, Any] | None:
        """
        Process a DataDog alert

        Args:
            alert: Raw alert data
            **kwargs: Processing options

        Returns:
            Processed alert or None if invalid
        """
        try:
            # Extract basic alert information
            alert_id = alert.get("id")
            alert_name = alert.get("name", "Unknown Alert")
            alert_message = alert.get("message", "")
            alert_status = alert.get("overall_state", "unknown")
            alert_priority = alert.get("priority", "P4")

            # Extract observables from HTTP request headers in samples
            observables = []
            if kwargs.get("extract_observables_from_alerts", True):
                observables = self._extract_observables_from_http_headers(alert)

            # Map priority to severity
            severity = self._map_priority_to_severity(alert_priority)

            # Extract attack type from alert (for security signals)
            attack_type = alert.get("attack_type", "unknown")

            # Create processed alert
            processed_alert = {
                "id": f"datadog-alert-{alert_id}",
                "type": "alert",
                "name": alert_name,
                "description": alert_message,
                "status": alert_status,
                "priority": alert_priority,
                "severity": severity,
                "attack_type": attack_type,
                "observables": observables,
                "created": self._extract_timestamp(alert.get("created")),
                "modified": self._extract_timestamp(alert.get("modified")),
                "source_data": alert,
                "metadata": {
                    "source": "DataDog",
                    "alert_id": alert_id,
                    "import_timestamp": datetime.now(UTC).isoformat(),
                },
            }

            # Add context if enabled
            if kwargs.get("include_alert_context", True):
                processed_alert["context"] = self._extract_alert_context(alert)

            return processed_alert

        except Exception as e:
            self.helper.log_error(
                f"Error processing alert {alert.get('id', 'unknown')}: {str(e)}"
            )
            return None

    def _extract_observables_from_http_headers(
        self, alert: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Extract observables by recursively searching for specific fields in the response

        Args:
            alert: Alert data containing raw signal with samples

        Returns:
            List of extracted observables
        """
        observables = []

        try:
            # Get the raw signal data
            raw_signal = alert.get("raw_signal", {})
            if not raw_signal:
                self.helper.log_debug(
                    "No raw signal data available for observable extraction"
                )
                return observables

            # Per-alert observable-extraction details are logged at
            # ``debug`` level so a high-volume cycle (the per-cycle cap
            # is 10,000 signals) does not produce one info-level
            # "searching" / "extracted N observables" / "no observables"
            # line per alert in production. The cycle-level summary in
            # ``connector.py::run`` ("Import completed: N bundle(s) sent
            # (X alerts processed, Y STIX objects created, Z errors)")
            # already covers the operator-visible metrics; the
            # per-alert lines are a debug-only diagnostic.
            self.helper.log_debug(
                "Recursively searching response for observable fields"
            )

            # Single pass collecting every observable-bearing field
            # AND every email address embedded in any string leaf at
            # once. The previous shape called ``_find_values_by_key``
            # eight times against the same ``raw_signal`` tree —
            # O(K · N) traversal overhead (with ``K`` = number of
            # target keys, ``N`` = total node count) — and then ran
            # ``json.dumps(raw_signal)`` + ``re.findall(...)`` on the
            # serialized blob to scrape emails out, which allocated a
            # full copy of every signal as one giant string and
            # compiled the email regex per call. Both passes are now
            # folded into the same traversal via ``_find_values``'s
            # ``string_leaf_handler`` hook (the precompiled module-
            # level ``_EMAIL_RE`` does the per-leaf scan), so a
            # 10,000-signal cycle walks each signal tree exactly once
            # instead of eight (key search) + once (json.dumps) + once
            # (regex scan over the full dump).
            email_values: set[str] = set()

            def _scan_emails(leaf: str) -> None:
                # ``finditer`` (rather than ``findall``) so we can
                # collect into a set without materialising a per-leaf
                # list; dedup also fold here before the observable
                # list is built, so the downstream
                # ``unique_observables`` pass has less work to do.
                for match in _EMAIL_RE.finditer(leaf):
                    email_values.add(match.group(0))

            extracted = self._find_values(
                raw_signal,
                {
                    "client_ip",
                    "x-real-ip",
                    "x-forwarded-for",
                    "host",
                    "hostname",
                    "url",
                    "user-agent",
                    "useragent",
                },
                string_leaf_handler=_scan_emails,
            )
            client_ips = extracted["client_ip"]
            x_real_ips = extracted["x-real-ip"]
            x_forwarded_fors = extracted["x-forwarded-for"]
            hosts = extracted["host"]
            hostnames = extracted["hostname"]
            urls = extracted["url"]
            user_agents = extracted["user-agent"]
            useragents = extracted["useragent"]

            # Process IPs. Strip the value before storing in the
            # observable dict so the SCO ``value`` carried into the
            # converter is canonical: ``_is_valid_ipv4`` /
            # ``_is_valid_ipv6`` already validate ``.strip()``-ed
            # input, so without the same normalisation here a DataDog
            # signal that emits ``' 192.0.2.1 '`` (upstream padding
            # has been observed on ``client_ip`` values copied from
            # log lines) would either crash ``stix2.IPv4Address``
            # (which rejects whitespace-padded values) or — worse —
            # produce two distinct OpenCTI observables for the same
            # logical address (one padded, one canonical) on later
            # cycles. Centralise the strip in this loop so the
            # ``observables`` list never carries whitespace-padded
            # IP values regardless of which upstream key produced
            # them.
            all_ips = client_ips + x_real_ips
            for ip in all_ips:
                if not isinstance(ip, str):
                    continue
                ip = ip.strip()
                if not ip:
                    continue
                if self._is_valid_ipv4(ip):
                    observables.append(
                        {"type": "ip", "value": ip, "source": "field_search"}
                    )
                elif self._is_valid_ipv6(ip):
                    observables.append(
                        {"type": "ipv6", "value": ip, "source": "field_search"}
                    )

            # Process x-forwarded-for (can have multiple IPs)
            for xff in x_forwarded_fors:
                if isinstance(xff, str):
                    ips = [ip.strip() for ip in xff.split(",")]
                    for ip in ips:
                        if self._is_valid_ipv4(ip):
                            observables.append(
                                {"type": "ip", "value": ip, "source": "field_search"}
                            )
                        elif self._is_valid_ipv6(ip):
                            observables.append(
                                {"type": "ipv6", "value": ip, "source": "field_search"}
                            )

            # Process hosts/hostnames. ``host`` values from upstream
            # field searches may carry a ``:port`` suffix (e.g.
            # ``example.com:443``) or be a bracketed IPv6 literal
            # (``[2001:db8::1]:443`` — the canonical RFC-3986
            # ``host`` production for an HTTP ``Host`` header that
            # carries an IPv6 address). ``host.split(":")[0]`` is
            # wrong for the IPv6 case — it would yield ``"[2001"``
            # and drop the observable entirely.
            #
            # Bracketed values can carry an IPv6 address that does
            # NOT appear anywhere else in the signal (the upstream
            # ``client_ip`` / ``x-real-ip`` / ``x-forwarded-for``
            # passes do not always cover the Host header), so we
            # cannot just skip them — we have to strip the brackets
            # (and the optional ``:<port>`` suffix) and emit an
            # ``ipv6`` observable when the inner value is a valid
            # IPv6 literal. If the inner value is not a valid IPv6
            # we fall through silently (a bracketed non-IPv6 host is
            # not a valid RFC-3986 production and is not a domain
            # candidate either). For non-bracketed values we keep
            # the previous shape: only strip a trailing ``:<digits>``
            # before passing to ``_is_valid_domain`` so we never
            # break a domain whose right-hand side happens to be
            # non-numeric.
            all_hosts = hosts + hostnames
            for host in all_hosts:
                if not isinstance(host, str):
                    continue
                # Normalise whitespace up-front so every downstream
                # branch (bracketed-IPv6 / domain-with-port / plain
                # domain) sees the canonical value: ``_is_valid_ipv6``
                # / ``_is_valid_domain`` already validate against the
                # ``.strip()``-ed input, but the observable dict was
                # storing the raw padded value — producing duplicate
                # OpenCTI SCOs across cycles for the same logical
                # host and risking ``stix2`` constructor rejection.
                host = host.strip()
                if not host:
                    continue
                if host.startswith("["):
                    closing = host.find("]")
                    if closing == -1:
                        continue
                    inner = host[1:closing].strip()
                    if self._is_valid_ipv6(inner):
                        observables.append(
                            {
                                "type": "ipv6",
                                "value": inner,
                                "source": "field_search",
                            }
                        )
                    continue
                domain = host
                if ":" in domain:
                    head, _, tail = domain.rpartition(":")
                    if tail.isdigit():
                        domain = head
                if self._is_valid_domain(domain):
                    observables.append(
                        {
                            "type": "domain",
                            "value": domain,
                            "source": "field_search",
                        }
                    )

            # Process URLs.
            #
            # The raw URL string is **not** preserved verbatim when it
            # carries basic-auth userinfo (``https://user:pass@host/x``).
            # ``_is_valid_url`` deliberately accepts userinfo (DataDog
            # signals legitimately carry such URLs in HTTP samples and
            # rejecting them would silently drop real observables), but
            # the URL observable persisted into OpenCTI MUST NOT carry
            # the credentials. ``_sanitize_url_value`` rebuilds the URL
            # from the parsed components without userinfo (scheme,
            # host, port, path, query, fragment are all preserved for
            # their threat-intel value — only the credentials are
            # stripped). When no userinfo is present the original
            # string flows through unchanged so observable identity
            # stays stable on signals without basic-auth URLs.
            for url in urls:
                if isinstance(url, str) and self._is_valid_url(url):
                    sanitized_url = self._sanitize_url_value(url)
                    if sanitized_url:
                        observables.append(
                            {
                                "type": "url",
                                "value": sanitized_url,
                                "source": "field_search",
                            }
                        )

            # Process user-agents. Strip the value before storing in
            # the observable dict so the SCO ``value`` carried into the
            # converter is canonical and matches the same per-extraction
            # normalisation already applied to ``ip`` / ``host`` /
            # ``url`` above. Without the strip:
            #
            # * The per-alert ``unique_observables`` dedup below keys on
            #   the raw value, so a single signal that carries the same
            #   user-agent twice with whitespace padding (e.g. one in
            #   the request and one in the upstream proxy's mirror of
            #   it) would emit two ``{type, value}`` dict entries that
            #   never collapse, even though they map to the same
            #   ``CustomObservableUserAgent`` SCO downstream.
            # * The converter's ``_create_observable_object`` does
            #   strip again at the SCO-construction site (defence in
            #   depth), but storing the canonical value here keeps the
            #   importer-side dedup contract truthful and avoids
            #   emitting duplicate dict entries that the converter
            #   then has to collapse via deterministic id.
            all_user_agents = user_agents + useragents
            for ua in all_user_agents:
                if not isinstance(ua, str):
                    continue
                ua = ua.strip()
                if not ua:
                    continue
                observables.append(
                    {"type": "user-agent", "value": ua, "source": "field_search"}
                )

            # Emails were collected in the same traversal as the field
            # search above via the ``_scan_emails`` callback — no
            # second walk of the signal tree and no
            # ``json.dumps(raw_signal)`` allocation needed. Iterate
            # the deduped set into the observable list here so the
            # downstream ``unique_observables`` pass still gets a
            # consistent ``{type, value, source}`` shape per entry.
            for email in email_values:
                observables.append(
                    {"type": "email", "value": email, "source": "field_search"}
                )

            # Deduplicate observables
            seen = set()
            unique_observables = []
            for obs in observables:
                key = (obs["type"], obs["value"])
                if key not in seen:
                    seen.add(key)
                    unique_observables.append(obs)

            # Per-alert observable-count summary kept at ``debug`` for
            # the same reason as the "searching" line above — info /
            # warning here would emit one line per signal in a cycle
            # that can carry up to ``_MAX_SIGNALS_PER_CYCLE`` alerts.
            # The "no observables extracted" branch is also a debug
            # signal: it is the expected outcome on signals that do
            # not carry HTTP-header observables (e.g. log-only rules)
            # and a warning here would have flagged thousands of
            # benign cycles per day.
            if unique_observables:
                type_counts = {}
                for obs in unique_observables:
                    obs_type = obs["type"]
                    type_counts[obs_type] = type_counts.get(obs_type, 0) + 1

                summary = ", ".join(
                    [f"{count} {obs_type}" for obs_type, count in type_counts.items()]
                )
                self.helper.log_debug(
                    f"Extracted {len(unique_observables)} unique observables: {summary}"
                )
            else:
                self.helper.log_debug("No observables extracted from response")

            return unique_observables

        except Exception as e:
            self.helper.log_error(f"Error extracting observables: {str(e)}")
            import traceback

            self.helper.log_error(traceback.format_exc())
            return observables

    def _find_values(
        self,
        data: Any,
        target_keys: set[str],
        string_leaf_handler=None,
    ) -> dict[str, list[Any]]:
        """
        Recursively search ``data`` once and return every value seen
        under any of ``target_keys``.

        One-pass replacement for the previous ``_find_values_by_key``
        helper. The earlier shape was called separately for each key
        the caller wanted, which made the traversal cost grow linearly
        with the number of keys (O(K · N) with ``K`` = number of keys,
        ``N`` = total nodes in the signal tree). The DataDog Security
        Signal payload is deeply nested (``attributes.attributes.*``,
        ``samples[*]``, repeated ``http`` blocks etc.) so on a high-
        volume cycle that overhead was non-trivial.

        The optional ``string_leaf_handler`` callback is invoked once
        for every ``str`` leaf encountered during the walk — used by
        the caller to fold the per-signal email scan into the same
        traversal instead of doing a second ``json.dumps`` + regex
        pass over the full serialized payload (see the
        ``_extract_observables_from_http_headers`` call site for the
        rationale).

        Args:
            data: Data structure to search (dict, list, or scalar).
            target_keys: Set of key names to collect.
            string_leaf_handler: Optional callable invoked with each
                string leaf value seen during the traversal. Allows
                callers to opt into a single-pass scan over the same
                tree (e.g. scanning for email addresses) without a
                second walk. Defaults to ``None`` (no leaf scanning).

        Returns:
            Dict mapping every requested key to the list of values
            found for it. Keys with no matches are present with an
            empty list so callers do not need a ``.get(key, [])``
            guard. List values are flattened one level (matching the
            previous helper's behaviour).
        """
        results: dict[str, list[Any]] = {key: [] for key in target_keys}

        stack: list[Any] = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in target_keys:
                        if isinstance(value, list):
                            results[key].extend(value)
                        else:
                            results[key].append(value)
                    stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)
            elif string_leaf_handler is not None and isinstance(node, str):
                string_leaf_handler(node)

        return results

    def _is_valid_ipv4(self, ip: str) -> bool:
        """
        Validate IPv4 address.

        Delegates to :mod:`ipaddress` so every RFC-compliant IPv4
        literal (zero-padded octets, dotted-quad, etc.) is accepted
        identically to the rest of the standard library. The earlier
        hand-rolled regex rejected legitimate forms (and a few
        non-standard ones the stdlib explicitly tolerates), so a
        regex-only validator silently dropped real IPv4 observables
        depending on how DataDog serialised the value upstream.

        Args:
            ip: IP address string

        Returns:
            True if valid IPv4
        """
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.IPv4Address(ip.strip())
        except ValueError:
            return False
        return True

    def _is_valid_ipv6(self, ip: str) -> bool:
        """
        Validate IPv6 address.

        Same rationale as :meth:`_is_valid_ipv4` — the previous
        hand-rolled regex rejected common compressed forms (``::1``,
        ``2001:db8::1``, …) and silently dropped legitimate IPv6
        observables. ``ipaddress.IPv6Address`` accepts every RFC-5952
        production for free.

        Args:
            ip: IP address string

        Returns:
            True if valid IPv6
        """
        if not ip or not isinstance(ip, str):
            return False
        try:
            ipaddress.IPv6Address(ip.strip())
        except ValueError:
            return False
        return True

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain name

        Args:
            domain: Domain name string

        Returns:
            True if valid domain
        """
        if not domain:
            return False

        # Reject literal IPv4 addresses up front so we never accept a
        # raw IP as a domain — the IP-address observable path handles
        # those instead. The earlier shape rejected anything starting
        # with ``172.``, which dropped legitimate public hostnames
        # like ``172.example.com`` while only ``172.16.0.0/12`` is
        # actually a private range. Validating through ``ipaddress``
        # keeps that distinction correct.
        # ``ipaddress.AddressValueError`` is a ``ValueError`` subclass
        # (see ``cpython/Lib/ipaddress.py``), so catching the parent
        # is sufficient — the redundant tuple form would have
        # silently swallowed any future stdlib re-parenting too.
        try:
            ipaddress.IPv4Address(domain)
            return False
        except ValueError:
            pass

        domain_pattern = (
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        return bool(re.match(domain_pattern, domain))

    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL

        Args:
            url: URL string

        Returns:
            True if valid URL
        """
        if not url or not isinstance(url, str):
            return False

        # Switched from a hand-rolled regex to ``urllib.parse`` because
        # the regex shape was rejecting common URL productions that
        # DataDog signals legitimately carry:
        #
        # * Explicit ports — ``https://example.com:8443/path`` did not
        #   match the ``[a-zA-Z0-9-]`` host class (no ``:`` allowed
        #   between the host and the optional path), so any URL with
        #   a non-default port was silently dropped on the floor.
        # * Userinfo — ``https://user:pass@example.com/`` was rejected
        #   for the same reason (no ``@``/``:`` in the host class).
        # * IPv4 / IPv6 literal hosts — ``http://192.0.2.1/`` matched
        #   only because the digits happen to fit ``[a-zA-Z0-9]``, but
        #   ``http://[2001:db8::1]/`` did not (no brackets in the host
        #   class).
        #
        # ``urllib.parse.urlsplit`` handles every RFC-3986 host
        # production (reg-name, IP-literal, IPv4address) for free and
        # we only need to constrain the scheme to ``http``/``https``
        # (the only schemes the converter knows how to map to a STIX
        # ``url`` observable) and require a non-empty host. The host
        # check uses ``urlsplit.hostname`` because it strips userinfo
        # and the port for us, so a missing host (e.g. ``https:///x``)
        # still fails cleanly.
        try:
            parts = urlsplit(url.strip())
        except ValueError:
            return False

        return parts.scheme in ("http", "https") and bool(parts.hostname)

    def _sanitize_url_value(self, url: str) -> str | None:
        """Rebuild ``url`` without any basic-auth userinfo component.

        The HTTP samples in a DataDog Security Signal can carry URLs
        with embedded credentials (``https://user:pass@host/path``).
        ``_is_valid_url`` deliberately accepts that shape — rejecting
        it would drop legitimate threat-intel-bearing observables for
        the surrounding host / path — but the value persisted into
        OpenCTI MUST NOT carry the credentials. Without sanitisation
        the URL observable becomes a credential-leak vector: the
        secret is replicated across every consumer of the OpenCTI
        platform (UI, audit log, downstream stream connectors, …).

        Sanitisation strategy
        ---------------------

        * Strip userinfo. The URL is rebuilt by taking
          ``parts.netloc.rsplit("@", 1)[-1]`` so any
          ``username[:password]@`` prefix is dropped but the rest of
          the authority (host, optional ``:port``, and IPv6 brackets)
          is preserved verbatim. This avoids the IPv6-rebuild pitfall
          of going through ``parts.hostname`` + ``parts.port``:
          ``urlsplit().hostname`` strips the surrounding ``[]`` for
          IPv6 literals, so a rebuilt authority like
          ``2001:db8::1:443`` is ambiguous (a valid IPv6 in its own
          right) and would corrupt the URL observable.
        * Preserve scheme, host, port, path, query and fragment.
          These can carry indicators-of-compromise themselves (e.g.
          phishing kit paths, signed-token reconnaissance, fragment-
          based exfiltration) so silently dropping them would lose
          threat-intel value. Only credentials are stripped.
        * Returns the original string verbatim when no userinfo is
          present so observable identity stays stable across cycles
          for the typical credential-free URL — only credential-
          carrying URLs are normalised.

        Returns
        -------
        ``str``
            The sanitised URL on success, or the original ``url`` when
            parsing fails (defensive — never lose an observable
            because of a parser edge case; the upstream
            ``_is_valid_url`` already gated this on ``urlsplit``
            succeeding so the failure branch should be unreachable).
        ``None``
            When the input is empty / not a string.
        """
        if not url or not isinstance(url, str):
            return None
        # Normalise whitespace once at the top so every return path
        # (parse-failure, no-userinfo fast path, userinfo-stripped
        # rebuild) yields the same canonical observable value.
        # ``_is_valid_url`` already gates membership on a parse of
        # ``url.strip()``; returning the unstripped original from
        # the no-userinfo branch below would have persisted the
        # whitespace-padded form into OpenCTI and produced duplicate
        # SCOs across cycles for the same logical URL.
        stripped = url.strip()
        if not stripped:
            return None
        try:
            parts = urlsplit(stripped)
        except ValueError:
            return stripped

        if not parts.username and not parts.password:
            return stripped

        # ``rsplit("@", 1)`` drops the userinfo prefix while keeping
        # any later ``@`` literals in the path / query / fragment
        # untouched (``urlsplit`` already split those off into
        # ``parts.path`` / ``parts.query`` / ``parts.fragment``). When
        # there is no ``@`` in ``parts.netloc`` the call returns the
        # netloc unchanged, but the userinfo guard above already
        # short-circuits that path so this branch only runs when an
        # ``@`` is guaranteed to be present.
        authority = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit(
            (parts.scheme, authority, parts.path, parts.query, parts.fragment)
        )

    def _extract_alert_context(self, alert: dict[str, Any]) -> dict[str, Any]:
        """
        Extract context information from alert.

        ``assignee`` is propagated alongside ``creator`` because
        :meth:`StixConverter._create_context_note` reads
        ``context.get("assignee")`` when rendering the context Note.
        ``DataDogClient._convert_signal_to_alert`` already populates
        ``alert["assignee"]`` (a dict with a ``name`` key) from the
        upstream ``workflow.triage.assignee`` field, but the importer
        used to drop it on the floor — so the Note rendered ``Creator:
        …`` while always omitting the ``Assignee:`` line, even on
        signals that explicitly carried one.

        Args:
            alert: Raw alert data

        Returns:
            Context dictionary
        """
        context = {
            "tags": alert.get("tags", []),
            "monitor_type": alert.get("type", "unknown"),
            "query": alert.get("query", ""),
            "options": alert.get("options", {}),
            "creator": alert.get("creator", {}),
            "assignee": alert.get("assignee", {}),
            "org_id": alert.get("org_id"),
        }

        return context

    def _map_priority_to_severity(self, priority: str) -> str:
        """
        Map DataDog priority to severity level — strict inverse of
        ``DataDogClient._convert_signal_to_alert`` (and the README
        configuration table):

        - ``critical`` → ``P1``  (client) becomes ``P1`` → ``critical``
        - ``high``     → ``P2``                       ``P2`` → ``high``
        - ``medium``   → ``P3``                       ``P3`` → ``medium``
        - ``low``      → ``P4``                       ``P4`` → ``low``
        - ``info``     → ``P5``                       ``P5`` → ``info``

        ``P0`` does not appear in the client's forward mapping but is
        documented by DataDog as a valid "above-critical" priority
        level — mapped to ``critical`` here as the closest STIX
        equivalent so a P0 signal never silently degrades to a lower
        severity.

        Args:
            priority: DataDog priority (P0-P5 or None)

        Returns:
            Severity level string
        """
        priority_map = {
            "P0": "critical",
            "P1": "critical",
            "P2": "high",
            "P3": "medium",
            "P4": "low",
            "P5": "info",
            None: "unknown",
        }

        return priority_map.get(priority, "unknown")

    def _extract_timestamp(self, timestamp_value: Any) -> datetime | None:
        """
        Extract and parse timestamp

        Args:
            timestamp_value: Timestamp in various formats

        Returns:
            Parsed datetime or None
        """
        # Explicit ``is None`` (rather than truthiness) so a legitimate
        # epoch value of ``0`` — i.e. ``1970-01-01T00:00:00Z`` — is
        # parsed instead of being silently dropped as "missing".
        # ``""`` strings are also rejected up front so the ``str``
        # branch below does not see empty input.
        if timestamp_value is None or timestamp_value == "":
            return None

        try:
            # Use the tuple form for ``isinstance`` (universally
            # supported across Python versions and the conventional
            # idiom in this repo). ``bool`` is intentionally NOT
            # accepted even though it is an ``int`` subclass — a
            # boolean here would almost certainly be a caller bug
            # rather than a literal epoch 0 / 1.
            if isinstance(timestamp_value, bool):
                return None
            if isinstance(timestamp_value, (int, float)):
                # ``datetime.fromtimestamp`` without ``tz`` returns a
                # naive datetime in local time — which makes the
                # resulting STIX ``created`` / ``modified`` shift
                # between hosts in different timezones (and the
                # deterministic-id helpers downstream assume UTC).
                # Anchor everything to UTC. DataDog API timestamps are
                # epoch milliseconds; epoch seconds also flow through
                # here, so accept both: values larger than ~year 5138
                # (10^11) are treated as milliseconds.
                ts = float(timestamp_value)
                if ts > 1e11:
                    ts /= 1000.0
                return datetime.fromtimestamp(ts, tz=UTC)
            elif isinstance(timestamp_value, str):
                # Try ISO format first.
                if "T" in timestamp_value:
                    parsed = datetime.fromisoformat(
                        timestamp_value.replace("Z", "+00:00")
                    )
                    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
                # Try other common formats.
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
                    try:
                        parsed = datetime.strptime(timestamp_value, fmt)
                        return parsed.replace(tzinfo=UTC)
                    except ValueError:
                        continue
        except Exception as e:
            self.helper.log_warning(
                f"Failed to parse timestamp '{timestamp_value}': {str(e)}"
            )

        return None
