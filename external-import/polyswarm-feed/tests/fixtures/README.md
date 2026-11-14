# Test fixtures

Responses from the PolySwarm TAXII 2.1 server and the live hunting API, used
by the connector unit tests. Recorded fixtures were captured on 2026-11-10 with
read-only GET requests, trimmed, and passed through
`tests/tools/scrub_fixtures.py`. `tests/tests_connector/test_fixtures_scrubbed.py`
checks that nothing sensitive is left.

## Recorded

1. `taxii_discovery.json`: `GET /v3/stix/taxii2/`. Lists the three API roots,
   which live at `/v3/stix/<root>` (not under `/taxii2/`).
2. `taxii_api_root_trustgroup.json`: `GET /v3/stix/trustgroup/`.
3. `taxii_collections_trustgroup.json`, `taxii_collections_ransomware.json`,
   `taxii_collections_freemium.json`: `GET /v3/stix/<root>/collections/`. One
   collection per root.
4. `taxii_objects_trustgroup_page1.json`: first objects page, `limit=2`. Not
   trimmed, so per-engine object counts are as served.
5. `taxii_objects_trustgroup_page1.headers.json`: status and TAXII headers of
   that response (`X-TAXII-Date-Added-First`, `X-TAXII-Date-Added-Last`).
6. `taxii_objects_trustgroup_page2.json`: the page fetched with page 1's `next`.
7. `taxii_objects_ransomware_page1.json`, `taxii_objects_freemium_page1.json`:
   first page, `limit=2`. The freemium bundles carry an `attack-pattern` and a
   `uses` relationship.
8. `taxii_objects_empty.json`: objects request with `added_after` set to the
   capture time. The server returned HTTP 200 with `{}` (no `objects`, no
   `more`).
9. `hunt_live_page1.json`, `hunt_live_page2.json`:
   `GET /v3/hunt/live/list?since=43200&limit=3`, then the same with
   `offset=<page 1 offset>`. Both have `has_more: true` and an `offset` cursor.
10. `hunt_live_last_page.json`: `GET /v3/hunt/live/list?since=1440`, a final
    page (`has_more: false`, no `offset` key), trimmed to 4 hits covering
    malware family set and unset, detections set and unset.

Not stored as a file: `GET /v3/hunt/live/list?since=1` returned HTTP 204 with
an empty body.

## Synthetic

1. `hunt_live_page.synthetic.json`: built by hand from the documented live
   hunt field list, using the public EICAR test file hashes. No recorded hit
   had `matched_strings` or `yara` populated, so the first hit fills them in.
   The `matched_strings` element shape (`identifier`, `offset`, `data`) and the
   boolean `matched_strings_dropped` are assumptions, not observed values.

## Changes from the live responses

1. Trimming: in `taxii_objects_trustgroup_page2.json` and the ransomware and
   freemium pages, each sample keeps 3 per-engine `malware-analysis` objects
   plus the sandbox one (`dynamic-analysis-of`); relationships to dropped
   objects were removed. Every object type and relationship type seen live is
   still present.
2. Paging cursors (`next`, `offset`) are opaque encrypted tokens; they are
   replaced with `REDACTED_CURSOR_<n>`.
3. The TAXII `contact` email is replaced with `REDACTED_EMAIL`.
4. Live hunt `id`, `instance_id` and `livescan_id` values are replaced with
   synthetic numbers of the same length, and rule names with
   `example_rule_<n>`, since rule names can reveal what an account monitors.
   A non-empty `yara` source is replaced with a placeholder rule under the
   synthetic name, for the same reason.

## Notes for tests

1. Each entry in a page's `objects` list is a full STIX bundle for one sample.
2. The sandbox `malware-analysis` object (product `cape`) lists
   `analysis_sco_refs` (ipv4-addr, network-traffic, domain-name, file) whose
   objects are not included in the bundle.
3. In every recorded bundle the three hash indicators (MD5, SHA-1, SHA-256)
   share one STIX `id`, and the three `indicates` relationships from it have
   identical `source_ref` and `target_ref`. Importing them by id as served
   keeps only one of the three patterns.
4. The family `malware` object (`is_family: true`) has the same id suffix as
   the bundle; the sample `malware` object (`is_family: false`) has the same
   suffix as the `file` object.
5. `tags` on a live hunt hit is a JSON encoded string (`"{}"`), not an object.
