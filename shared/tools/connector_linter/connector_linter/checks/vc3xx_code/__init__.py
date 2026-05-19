"""VC3xx — Code quality checks.

VC301: Connector must define an author identity.
VC302: Author must be referenced on STIX entities (created_by_ref).
VC303: CONNECTOR_TYPE must be defined in application code, not read from env.
VC304: Ensure TLP markings are checked (check_max_tlp).
VC305: Connector must implement Base Settings from connectors-sdk.
VC306: Connector log level should default to 'error'.
VC307: Except blocks should use error/warning logging, not debug/info.
VC308: Main entry point must use traceback for error handling.
VC309: Connector must use only absolute imports, no relative imports.
VC310: External references must not be added by default to non-Identity objects.
VC311: Connector should use TLP markings on entities with appropriate level.
VC312: send_stix2_bundle must use cleanup_inconsistent_bundle=True.
VC313: STIX SDO/SRO objects must use pycti.XXX.generate_id() for deterministic IDs.
VC314: External-import connectors must use schedule_process or schedule_iso.
VC315: Connector must call initiate_work before processing.
VC316: Connector must close work with to_processed after processing.
VC317: initiate_work should only be called when data is available.
VC318: Internal-enrichment connectors must use helper.listen().
VC319: Enrichment connector must return original bundle when not in scope.
VC320: Enrichment connector must enforce TLP access control.
VC321: Enrichment connector must be playbook-compatible.
VC322: Enrichment connector must read data['stix_objects'] (former bundle).
VC323: Stream connectors must use helper.listen_stream().
VC324: Relationship should not set both start_time and stop_time.
"""
