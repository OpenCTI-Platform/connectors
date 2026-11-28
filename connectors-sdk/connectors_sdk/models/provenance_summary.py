"""ProvenanceSummary."""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self

from connectors_sdk.models.enums import ProvenanceSourceKind
from connectors_sdk.models.exceptions import ProvenanceSummaryError
from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
)

STIX_EXT_OCTI_PROVENANCE = "extension-definition--283daa2f-7739-5345-a110-19d73676f670"
"""Id of the `opencti-provenance` STIX property extension exported by OpenCTI."""

_Count = Annotated[StrictInt, Field(ge=0)]
_FieldName = Annotated[StrictStr, Field(min_length=1)]


def _to_read_only_mapping(
    value: Mapping[ProvenanceSourceKind, int],
) -> Mapping[ProvenanceSourceKind, int]:
    """Copy a validated mapping into a read-only view."""
    return MappingProxyType(dict(value))


def _to_dict(
    value: Mapping[ProvenanceSourceKind, int],
) -> dict[ProvenanceSourceKind, int]:
    """Serialize a read-only mapping as a plain dict."""
    return dict(value)


def _no_sources() -> Mapping[ProvenanceSourceKind, int]:
    """Return an empty read-only mapping."""
    return MappingProxyType({})


_SourcesByKind = Annotated[
    Mapping[ProvenanceSourceKind, _Count],
    AfterValidator(_to_read_only_mapping),
    PlainSerializer(_to_dict, return_type=dict[ProvenanceSourceKind, int]),
]


class ProvenanceSummary(BaseModel):
    """Read-only summary of the provenance OpenCTI records for a STIX object.

    OpenCTI records which sources asserted each Stix Core Object (SDO and SCO),
    Stix Core Relationship and sighting, and when. It exports a summary of these
    assertions in the `opencti-provenance` STIX property extension
    (`STIX_EXT_OCTI_PROVENANCE`) of the objects it streams and exports. The summary
    holds counts, dates and flags only: never source names nor user emails.

    The model is read-only. It is frozen and its collections are immutable (a tuple
    and a read-only mapping). It is not a `BaseObject`: it has no `to_stix2_object`
    method, and no write model accepts it nor any STIX `extensions` property.
    Connectors read provenance, they never send it: OpenCTI computes it from who
    writes the data, never from the content of the ingested bundles.

    For forward compatibility, payload fields unknown to this SDK version are
    ignored, and unknown source kinds are kept in `sources_by_kind` (with the
    `UserWarning` that `ProvenanceSourceKind` emits for out-of-vocabulary values).

    Examples:
        >>> summary = ProvenanceSummary.from_stix(stix_object)
        >>> if summary is not None and not summary.single_sourced:
        ...     connectors = summary.sources_by_kind.get(ProvenanceSourceKind.CONNECTOR, 0)

    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    corroboration_count: _Count = Field(
        description="Number of distinct sources asserting the fact, every source counted.",
    )
    assertions_count: _Count = Field(
        description=(
            "Sum of the assertion counts of the sources OpenCTI details "
            "(up to 200 per fact: the earliest and the most recently active)."
        ),
    )
    first_asserted: AwareDatetime | None = Field(
        default=None,
        description="When a source asserted the fact for the first time.",
    )
    last_asserted: AwareDatetime | None = Field(
        default=None,
        description="When a source asserted the fact for the last time.",
    )
    single_sourced: StrictBool = Field(
        description="Whether exactly one source asserts the fact.",
    )
    has_conflicts: StrictBool = Field(
        description="Whether sources proposed conflicting values for some attributes.",
    )
    conflicting_fields: tuple[_FieldName, ...] = Field(
        default=(),
        description="Names of the attributes for which sources proposed conflicting values.",
    )
    freshness_stale: StrictBool = Field(
        description="Whether a knowledge freshness rule flagged the fact as stale.",
    )
    sources_by_kind: _SourcesByKind = Field(
        default_factory=_no_sources,
        description=(
            "Number of distinct sources asserting the fact, per kind of source, "
            "among the sources OpenCTI details (up to 200 per fact)."
        ),
    )
    extension_type: Literal["property-extension"] = Field(
        default="property-extension",
        description="STIX extension type of the provenance extension.",
    )

    @classmethod
    def from_stix(cls, stix_object: Mapping[str, Any]) -> Self | None:
        """Read the provenance summary of a STIX object exported by OpenCTI.

        Args:
            stix_object: The STIX 2.1 object, either a plain dict (for instance the
                data of a stream event) or a stix2 library object.

        Returns:
            The provenance summary, or None when the object carries no provenance
            extension (OpenCTI omits it when the provenance is unknown).

        Raises:
            TypeError: If `stix_object` is not a mapping.
            ProvenanceSummaryError: If the provenance extension is present but malformed.

        """
        if not isinstance(stix_object, Mapping):
            raise TypeError(
                "Expected a STIX object as a mapping (dict or stix2 object), "
                f"got {type(stix_object).__name__}."
            )
        extensions = stix_object.get("extensions")
        if extensions is None:
            return None
        stix_id = stix_object.get("id")
        if not isinstance(extensions, Mapping):
            raise ProvenanceSummaryError(
                f"Malformed STIX object {stix_id}: 'extensions' must be a mapping, "
                f"got {type(extensions).__name__}."
            )
        payload = extensions.get(STIX_EXT_OCTI_PROVENANCE)
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise ProvenanceSummaryError(
                f"Malformed OpenCTI provenance extension on {stix_id}: "
                f"expected a mapping, got {type(payload).__name__}."
            )
        try:
            return cls.model_validate(dict(payload))
        except ValidationError as err:
            invalid_fields = sorted(
                {
                    ".".join(str(part) for part in error["loc"])
                    for error in err.errors(include_url=False)
                }
            )
            raise ProvenanceSummaryError(
                f"Malformed OpenCTI provenance extension on {stix_id}: "
                f"invalid {', '.join(invalid_fields)}."
            ) from err

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        """Return a copy of the summary, validating the updated values.

        Pydantic does not validate `update` values: a copy could otherwise hold a
        negative count or a mutable collection.

        Args:
            update: Values to change in the copy.
            deep: Whether to make a deep copy (fields are immutable either way).

        Returns:
            A new summary.

        Raises:
            ValueError: If `update` names a field the model does not define.
            ValidationError: If an updated value is invalid.

        """
        if not update:
            return super().model_copy(deep=deep)
        unknown_fields = set(update) - set(type(self).model_fields)
        if unknown_fields:
            raise ValueError(
                f"Unknown {type(self).__name__} fields: {', '.join(sorted(unknown_fields))}."
            )
        return type(self).model_validate(
            {**self.model_dump(exclude_unset=True), **update}
        )

    def __hash__(self) -> int:
        """Hash the summary consistently with its equality.

        The default hash of frozen pydantic models fails on mapping fields. Mappings
        are hashed as the frozenset of their items, so that equal summaries hash
        equally whatever the key order.
        """
        values = tuple(
            frozenset(value.items()) if isinstance(value, Mapping) else value
            for value in (getattr(self, name) for name in type(self).model_fields)
        )
        return hash((type(self), values))

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Self:
        """Return a shallow copy: every field is immutable, so it can be shared."""
        return self.__copy__()

    def __reduce__(self) -> tuple[Any, ...]:
        """Pickle the summary through its dict representation."""
        return (type(self).model_validate, (self.model_dump(exclude_unset=True),))
