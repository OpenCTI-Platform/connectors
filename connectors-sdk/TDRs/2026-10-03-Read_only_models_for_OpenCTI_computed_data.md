# TDR: Read-only models for OpenCTI computed data

## Overview

This TDR introduces read-only models in `connectors_sdk.models`: pydantic models that connectors read from STIX objects exported by OpenCTI, and never send back.
The first one is `ProvenanceSummary`, parsed from the `opencti-provenance` STIX property extension.

---

## Motivation

OpenCTI records which sources asserted each Stix Core Object, Stix Core Relationship and sighting (provenance, corroboration and freshness), and exports a summary of these assertions in a STIX property extension.
Stream and enrichment connectors need a typed, validated way to read that summary, for instance to forward only corroborated knowledge.

The existing OCTI models are write models: they are built by connectors and converted with `to_stix2_object()` into the bundles sent to OpenCTI.
Provenance is the opposite: OpenCTI computes it from who writes the data, and ignores it in ingested bundles.
A connector must be able to read it, but no API of the SDK should suggest it can be written.

---

## Proposed Solution

- `ProvenanceSummary` inherits from `pydantic.BaseModel`, not from `BaseObject`: it has no `to_stix2_object()` method, and no write model has a field accepting it (write models forbid extra inputs, so neither a summary nor a raw STIX `extensions` property can be passed to them).
- The model is frozen (`frozen=True`), contrary to the write models (see [Rely on Pydantic OCTI Models](./2025-06-06-Rely_on_pydantic_OCTI_models.md)): a value read from OpenCTI has no reason to be modified. Its collections are immutable too: `tuple` for lists, a read-only mapping (`types.MappingProxyType`) for dicts, with the hash, copy and pickle support this requires.
- `ProvenanceSummary.from_stix(stix_object)` accepts any mapping, which covers plain dicts (stream events, JSON bundles) and `stix2` library objects (which are mappings and keep unregistered property extensions as dicts).
  - It returns `None` when the extension is absent: provenance is optional, and absence is not an error.
  - It raises `ProvenanceSummaryError` (a `ValueError`) when the extension is present but malformed, chaining the pydantic `ValidationError`. A malformed payload is a contract violation that the connector should log, not silently ignore.
- Values are strictly typed (`StrictInt`, `StrictBool`, timezone aware datetimes), counts are non-negative.
- Forward compatibility: unknown payload fields are ignored (`extra="ignore"`), and unknown source kinds are kept through the `_PermissiveEnum` based `ProvenanceSourceKind`.
- The extension definition id is exposed as `STIX_EXT_OCTI_PROVENANCE`.

---

## Advantages

- Connectors get a documented, validated and typed view of OpenCTI provenance with a single call.
- The read-only guarantee is structural (no conversion method, frozen model, write models rejecting it) and covered by tests.
- The same parser serves stream connectors (dicts) and connectors working with `stix2` objects.

---

## Disadvantages

- Read-only mappings are not natively supported by pydantic: the model needs a custom serializer, hash, deep copy and pickle support.
- Strict typing rejects a payload whose values would only be coercible (for instance a count sent as a string). This is intended: the contract is produced by OpenCTI, not by third parties.

---

## Alternatives Considered

1. **A write model (`BaseObject`) with a `to_stix2_object()` raising an error**: rejected, the method would advertise a capability that must not exist, and errors would only appear at runtime.
2. **Returning raw dicts**: rejected, every connector would re-implement validation and date parsing.
3. **Returning `None` on malformed payloads**: rejected, a sentinel value would hide contract violations (see [How to handle errors in connectors](../docs/HOW-TO-Handle-errors-in-connectors.md)).
4. **Mutable `dict` and `list` fields on a frozen model**: rejected, `frozen=True` only prevents attribute assignment, and the nested collections could still be modified.

---

## References

- OpenCTI umbrella issue: [Provenance, Corroboration and Freshness](https://github.com/OpenCTI-Platform/opencti/issues/18676) (consulted on 2026-10-03)
- [Pydantic frozen models](https://docs.pydantic.dev/latest/concepts/models/#faux-immutability) (consulted on 2026-10-03)
- [STIX 2.1 extension definitions](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_32j232tfvtly) (consulted on 2026-10-03)

---
