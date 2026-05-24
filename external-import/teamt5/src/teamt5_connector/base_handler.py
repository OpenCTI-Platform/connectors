from abc import ABC, abstractmethod
from datetime import datetime

# STIX 2.1 cyber observable types (SCOs). OpenCTI uses
# ``x_opencti_created_by_ref`` on SCOs because the STIX 2.1 spec only defines
# ``created_by_ref`` on SDOs/SROs; setting it on an SCO produces an invalid
# bundle and the platform will reject the object on import.
_STIX_SCO_TYPES = frozenset(
    {
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
    }
)

# Hard upper bound on consecutive failed pages before giving up on the
# current handler run. A regular ``schedule_iso`` cycle will pick up where
# we left off, so bailing out is safer than spinning forever.
_MAX_PAGE_FAILURES = 5


class BaseHandler(ABC):

    # The name of the handler, for use in logging.
    name = None
    # The API endpoint for retrieving objects of the corresponding type
    url_suffix = None
    # The key required to look up the objects in the response, as per the TeamT5 API
    response_key = None

    def __init__(self, client, helper, config, author, tlp_ref):
        """
        Initialize the BaseHandler: an abstract base class implementing the Template Method
        design pattern to allow for customisations for different object types to the otherwise
        consistent retrieval and posting processes.

        Subclasses implement the map_bundle_reference and create_additional_objects methods, allowing them
        to create additional STIX objects or otherwise alter the ways in which the retrieved data is handled.
        """
        self.client = client
        self.helper = helper
        self.config = config
        self.author = author
        self.tlp_ref = tlp_ref
        # Per-run success flags consumed by ``TeamT5Connector.process_message``
        # to decide whether the persisted ``last_run`` cursor can be safely
        # advanced. ``aborted`` flips to ``True`` when
        # ``retrieve_bundle_references`` bails out after
        # ``_MAX_PAGE_FAILURES`` consecutive failed pages; ``partial_push``
        # flips to ``True`` when ``push_objects`` failed to push every
        # retrieved bundle (e.g. one of the per-bundle STIX downloads
        # returned ``None`` / contained no objects / had no ``stix_url``).
        # Both reset to ``False`` at the start of each retrieval /
        # push pass so a previous-cycle failure does not stick.
        self.aborted: bool = False
        self.partial_push: bool = False

    @abstractmethod
    def map_bundle_reference(self, raw_bundle_ref: dict) -> dict:
        """
        Maps a bundle reference from the TeamT5 API based on the specifications delegated
        to subclasses.

        :param raw_bundle_ref: A dictionary of the raw bundle reference from the API before mapping.
        :return: A dictionary of the mapped bundle reference.
        """
        pass

    @abstractmethod
    def create_additional_objects(self, stix_content: list, bundle_ref: dict) -> list:
        """
        Creates any additional objects required to be alongside the STIX bundle retrieved from
        the TeamT5 API. Based on the specifications delegated to subclasses. For example: a Report
        for the Report Handler.

        :param stix_content: A list of all stix objects in the bundle corresponding to the bundle reference.
        :param bundle_ref: A dictionary of the current bundle reference containing bundle information.
        :return: A list containing the previous STIX content as well as any new objects.
        """
        pass

    def retrieve_bundle_references(self, last_run_timestamp: int) -> list:
        """
        Retrieves all bundle references from the TeamT5 API after the desired timestamp, of the type
        corresponding to the calling Handler.

        Bundle references are structures defined by the API that provide information about their
        contents as well as an endpoint URL to download their corresponding STIX bundle, for example,
        an IndicatorBundle reference.

        :param last_run_timestamp: The timestamp from which bundle references should be retrieved.
        :return: A list containing all bundle references published to the API since the last run timestamp.
        """

        # Build the listing URL from the user-configured base URL so the
        # connector targets the same host as the OAuth / API-key client
        # (private deployments, on-prem instances, staging, etc.). Falling
        # back to a hard-coded ``api.threatvision.org`` would silently bypass
        # ``TEAMT5_API_BASE_URL`` / ``teamt5.api_base_url`` for pagination
        # even though token exchange already honours it.
        url = f"{self.config.teamt5.api_base_url.rstrip('/')}{self.url_suffix}"
        retrieved_bundle_refs = []
        failure_count = 0
        # Reset success flags at the top of each retrieval pass so a
        # previous-cycle failure does not stick to the handler instance
        # (the connector instantiates each handler once and re-uses it
        # across scheduled runs).
        self.aborted = False

        while True:

            params = {
                "offset": len(retrieved_bundle_refs),
                "date[from]": last_run_timestamp,
            }

            # Pagination opts into the one-second throttle so tight
            # back-to-back listing GETs do not hammer the upstream API.
            # The same throttle is intentionally NOT applied to bundle
            # downloads in ``push_objects`` — see
            # ``Teamt5Client.request_data`` docstring for the rationale.
            data = self.client.request_data(url, params, throttle=True)
            if not data or not data.get("success"):
                failure_count += 1
                self.helper.connector_logger.warning(
                    f"Unable to retrieve {self.name}: response from server was unsuccessful "
                    f"(attempt {failure_count}/{_MAX_PAGE_FAILURES})"
                )
                if failure_count >= _MAX_PAGE_FAILURES:
                    self.helper.connector_logger.error(
                        f"Giving up on {self.name} retrieval after {failure_count} consecutive "
                        "failed pages; the next scheduled run will retry."
                    )
                    # Signal partial-failure to the caller so the
                    # connector's persisted ``last_run`` cursor is NOT
                    # advanced past the unprocessed listing tail —
                    # advancing it would silently skip every bundle
                    # that was published after ``last_run`` but before
                    # the page that failed.
                    self.aborted = True
                    break
                continue

            failure_count = 0

            # Using template method, map each bundle reference based on the retrieved data.
            bundle_refs = [
                self.map_bundle_reference(raw_ref)
                for raw_ref in data.get(self.response_key, [])
            ]

            self.helper.connector_logger.debug(
                f"Found {len(bundle_refs)} {self.name} references."
            )
            retrieved_bundle_refs.extend(bundle_refs)
            if len(bundle_refs) == 0:
                break

        return retrieved_bundle_refs

    def push_objects(self, work_id: str, bundle_refs: list) -> int:
        """
        Retrieves the bundle of STIX objects corresponding to each bundle reference
        and pushes them to OpenCTI.

        :param work_id: The id to be used in pushing said bundles.
        :param bundle_refs: A list of bundle references corresponding to the type of the Handler.
        :return: The number of bundles successfully pushed to OpenCTI.
        """

        # Reset the per-run flag so a previous-cycle partial-failure does
        # not leak into the current pass (the handler is re-used across
        # ``schedule_iso`` invocations).
        self.partial_push = False
        num_bundles_pushed = 0
        # Count refs the connector actually attempted to push — i.e.
        # those carrying a ``stix_url`` we can dereference. References
        # that the upstream TeamT5 listing returns without a
        # ``stix_url`` are intentionally non-pushable (the listing
        # surfaces them for visibility but ``BaseHandler.push_objects``
        # has nothing to download), so they MUST be excluded from the
        # ``partial_push`` denominator below: counting them as
        # failures would treat every cycle that sees a non-pushable
        # ref as a partial failure, freeze the persisted ``last_run``
        # cursor in place forever, and re-process the same bundles on
        # every subsequent run. Transport / decode failures on a
        # ``stix_url`` we DID attempt to download are still counted as
        # partial failures — those bundles can be retried on the next
        # cycle and the cursor should hold so they are not silently
        # skipped.
        pushable_refs = 0

        for bundle_ref in bundle_refs:

            self.helper.connector_logger.debug(
                f"Processing {self.name} from: {datetime.fromtimestamp(bundle_ref.get('created_at')).strftime('%H:%M %d/%m/%Y')}"
            )

            bundle_url = bundle_ref.get("stix_url")
            if bundle_url is None:
                self.helper.connector_logger.warning(
                    f"Skipping {self.name}: listing reference has no STIX url to download."
                )
                continue

            pushable_refs += 1

            # Retrieve the STIX Bundle corresponding to the bundle reference
            stix_bundle = self.client.request_data(bundle_url)
            if stix_bundle is None:
                continue

            stix_content = stix_bundle.get("objects")
            if stix_content is None or len(stix_content) == 0:
                self.helper.connector_logger.info("API Returned bundle with no items.")
                continue

            # Append author and TLP Marking to objects in the bundle
            stix_content = [self._append_author_and_tlp(obj) for obj in stix_content]

            # Create additional STIX Objects for required Handlers (e.g Report object for Report Handler)
            stix_content = self.create_additional_objects(stix_content, bundle_ref)

            stix_content.extend([self.author, self.tlp_ref])

            # Push the bundle to the platform
            bundle = self.helper.stix2_create_bundle(stix_content)
            self.helper.send_stix2_bundle(
                bundle, work_id=work_id, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(
                f"{self.name} with {len(stix_content)} objects pushed to OpenCTI successfully."
            )
            num_bundles_pushed += 1

        # Signal partial failure to the caller (consumed by
        # ``TeamT5Connector.process_message`` to decide whether the
        # persisted ``last_run`` cursor can be advanced). The
        # denominator is ``pushable_refs`` (refs with a ``stix_url``),
        # NOT ``len(bundle_refs)`` — references the upstream listing
        # surfaced without a ``stix_url`` are intentionally
        # non-pushable and must not freeze the cursor. Refs that DID
        # carry a ``stix_url`` but fell through a download / decode /
        # empty-body ``continue`` branch above ARE counted as
        # failures so the next scheduled cycle retries them.
        if num_bundles_pushed < pushable_refs:
            self.partial_push = True

        return num_bundles_pushed

    def _append_author_and_tlp(self, stix_object: dict) -> dict:
        """
        Appends an author and TLP Marking to a pre-existing STIX object in dictionary form.

        STIX 2.1 only defines ``created_by_ref`` on SDOs/SROs. For cyber
        observables (SCOs) OpenCTI exposes the same concept via the
        ``x_opencti_created_by_ref`` custom property; setting the standard
        ``created_by_ref`` on an SCO produces an invalid bundle that the
        platform rejects on import. ``marking-definition`` objects are
        STIX Meta Objects (SMOs) and accept neither ``created_by_ref``
        nor ``object_marking_refs`` — attaching either produces an
        invalid SMO (and, in the ``object_marking_refs`` case, a noisy
        self-reference when the upstream bundle already carries the same
        marking-definition the connector is about to append).

        :param stix_object: A STIX object in dictionary form.
        :return: The same STIX object in dictionary form, with the desired TLP Marking and author attached on the correct field.
        """

        # Attribute-style ``.id`` access matches the contract used by
        # ``ReportHandler._create_report`` (``self.author.id`` /
        # ``self.tlp_ref.id``) and the canonical stix2 access pattern.
        # ``TeamT5Connector`` already passes real ``stix2.Identity`` /
        # ``stix2.MarkingDefinition`` instances into every handler, so we
        # standardise on the same accessor here instead of mixing dict-style
        # subscripting on the BaseHandler path and attribute access on the
        # Report subclass.
        author_id = self.author.id
        tlp_id = self.tlp_ref.id

        obj_type = stix_object.get("type")
        if obj_type == "marking-definition":
            # SMO: skip both ``created_by_ref`` and ``object_marking_refs``
            # — the field is invalid on the SMO itself and would also
            # introduce a self-reference when the upstream bundle already
            # contains the same marking the connector appends.
            return stix_object

        if obj_type in _STIX_SCO_TYPES:
            stix_object["x_opencti_created_by_ref"] = author_id
        elif obj_type:
            stix_object["created_by_ref"] = author_id

        # Append TLP Marking on every SDO/SRO/SCO (the SMO branch
        # above already returned).
        stix_object["object_marking_refs"] = stix_object.get(
            "object_marking_refs", []
        ) + [tlp_id]

        return stix_object
