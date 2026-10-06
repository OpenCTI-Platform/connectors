# macadress.com STIX Output

STIX 2.1 objects the `macadress` connector sends to OpenCTI when enriching a
`Mac-Addr` observable. The exact bundle depends on the API response for
`GET /v1/mac/{mac}`, the TLP markings on the observable, and the
`MACADRESS_CREATE_NOTE` / `MACADRESS_CREATE_VENDOR_IDENTITY` settings.

## High-level behavior

The connector starts from a single `mac-addr` observable already in the incoming
enrichment payload. It then:

- updates that observable in place through OpenCTI STIX extension fields
- appends an author Identity
- appends a vendor Organization Identity and one relationship, when the API
  reports a reliable vendor lookup
- appends a single summary Note, when `MACADRESS_CREATE_NOTE=true`

An observable that the API cannot parse as a MAC address, or a `400` response,
returns the original bundle unchanged with no extra objects.

## Existing input observable

The `mac-addr` observable is not recreated. It is updated via
`OpenCTIStix2.put_attribute_in_extension(...)`:

- `x_opencti_description` - markdown summary of the analysis
- `score` - `MACADRESS_DEFAULT_SCORE` (default `30`)
- `labels` - always `macadress`; plus, when present:
  - the device category (for example `smartphone`, `router`, `virtual_machine`)
  - `locally-administered` or `universally-administered`
  - `mac-randomized` when the API reports randomization confidence `possible` or `likely`
  - `virtualization:<platform>` (for example `virtualization:vmware`)
  - `special-use:<type>` (for example `special-use:multicast`)
- `external_references`:
  - `{ "source_name": "macadress.com", "url": "https://macadress.com/lookup/<mac>" }`
  - `{ "source_name": "macadress.com (vendor)", "url": "<vendor page>" }` when the API returns a vendor `lookup_url`

## Author Identity

Appended once per bundle, used as `created_by_ref` for generated objects.

- STIX type: `identity`
- `name`: `macadress.com`
- `identity_class`: `organization`

## Vendor Organization Identity

Created when the API returns an `organization` and `vendor_lookup_reliable` is
not `false`, and `MACADRESS_CREATE_VENDOR_IDENTITY=true`.

- STIX type: `identity`
- `identity_class`: `organization`
- `name`: the organization string from the API (verbatim)
- OpenCTI custom properties: `x_opencti_organization_type = vendor`,
  `x_opencti_labels = ["macadress"]`, `x_opencti_reliability = "B - Usually reliable"`,
  `x_opencti_aliases = [country]` when a country is known

Relationship created:

- `mac-addr --related-to--> identity`, with a description naming the registered block holder

The id is deterministic on the organization name, so re-enriching a MAC from the
same vendor upserts the identity instead of duplicating it.

## Summary Note

Created when `MACADRESS_CREATE_NOTE=true` (default).

- STIX type: `note`
- `abstract`: `macadress.com analysis of <mac>`
- `object_refs`: the input `mac-addr`
- custom properties: `note_types = ["external"]`
- id is stable per MAC (`Note.generate_id(None, "macadress.com enrichment of <mac>")`),
  so re-enrichment updates the note rather than adding another

## Relationship types used

- `related-to` - `mac-addr` to vendor `identity`

## Example bundle shape

Simplified, not a byte-for-byte rendering:

```json
{
  "type": "bundle",
  "objects": [
    { "type": "identity", "name": "macadress.com", "identity_class": "organization" },
    { "type": "identity", "name": "Apple, Inc.", "identity_class": "organization",
      "x_opencti_organization_type": "vendor" },
    { "type": "relationship", "relationship_type": "related-to",
      "source_ref": "mac-addr--...", "target_ref": "identity--..." },
    { "type": "note", "abstract": "macadress.com analysis of F0:18:98:11:22:33" }
  ]
}
```
