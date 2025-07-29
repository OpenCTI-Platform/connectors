"""These are the custom STIX properties and observation types used internally by OpenCTI."""

from stix2 import CustomObject, CustomObservable, ExternalReference
from stix2.properties import (
    ListProperty,
    ReferenceProperty,
    StringProperty,
)


# Custom objects


@CustomObject(
    "case-incident",
    [
        ("name", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        ("description", StringProperty()),
        ("severity", StringProperty()),
        ("priority", StringProperty()),
        ("response_types", ListProperty(StringProperty)),
        ("x_opencti_workflow_id", StringProperty()),
        ("x_opencti_assignee_ids", ListProperty(StringProperty)),
        ("external_references", ListProperty(ExternalReference)),
        (
            "object_refs",
            ListProperty(
                ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version="2.1")
            ),
        ),
    ],
)
class CustomObjectCaseIncident:
    """Case-Incident object."""

    pass


# Custom observables


@CustomObservable(
    "hostname",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableHostname:
    """Hostname observable."""

    pass


@CustomObservable(
    "text",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableText:
    """Text observable."""

    pass


@CustomObservable(
    "user-agent",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableUserAgent:
    """User-Agent observable."""

    pass
