"""Unit tests for the refanging of the observables of an extracted bundle.

Documents defang their indicators ("admin[at]filigran[dot]io") and the
extraction used to forward that spelling as is: OpenCTI rejected the
observables (INCORRECT_OBSERVABLE_FORMAT), then the report referencing them
(MISSING_REFERENCE_ERROR).
"""

import json
import sys
import uuid
from pathlib import Path

import pycti
import pytest
import stix2

sys.path.append(str((Path(__file__).resolve().parent.parent / "src")))

from import_doc_ai.refang import (
    RefangedObservable,
    UnrefangedObservable,
    refang_bundle_observables,
    refang_observable_value,
)

ISSUE_EMAIL = "admin[at]filigran[dot]io"
ISSUE_IPV6 = "2001[:]0db8[:]85a3[:]0000[:]0000[:]8a2e[:]0370[:]7334"

NOTATIONS = [
    pytest.param("domain-name", "filigran[.]io", "filigran.io", id="[.]"),
    pytest.param("domain-name", "filigran(.)io", "filigran.io", id="(.)"),
    pytest.param("domain-name", "filigran{.}io", "filigran.io", id="{.}"),
    pytest.param("domain-name", "filigran[dot]io", "filigran.io", id="[dot]"),
    pytest.param("domain-name", "filigran(dot)io", "filigran.io", id="(dot)"),
    pytest.param("domain-name", "filigran{dot}io", "filigran.io", id="{dot}"),
    pytest.param("domain-name", "filigran dot io", "filigran.io", id="spaced dot"),
    pytest.param("domain-name", "filigran [ . ] io", "filigran.io", id="spaced [ . ]"),
    pytest.param("domain-name", "FILIGRAN[DOT]IO", "FILIGRAN.IO", id="[DOT]"),
    pytest.param(
        "hostname", "srv01[.]filigran[.]io", "srv01.filigran.io", id="hostname"
    ),
    pytest.param("email-addr", "admin[at]filigran.io", "admin@filigran.io", id="[at]"),
    pytest.param(
        "email-addr", "admin(at)filigran(.)io", "admin@filigran.io", id="(at)"
    ),
    pytest.param(
        "email-addr", "admin{at}filigran{dot}io", "admin@filigran.io", id="{at}"
    ),
    pytest.param("email-addr", "admin[@]filigran[.]io", "admin@filigran.io", id="[@]"),
    pytest.param("email-addr", "admin(@)filigran.io", "admin@filigran.io", id="(@)"),
    pytest.param(
        "email-addr", "admin [AT] filigran [DOT] io", "admin@filigran.io", id="[AT]"
    ),
    pytest.param(
        "email-addr", "admin at filigran dot io", "admin@filigran.io", id="spaced at"
    ),
    pytest.param("ipv4-addr", "192[.]168[.]1[.]1", "192.168.1.1", id="ipv4 [.]"),
    pytest.param(
        "ipv4-addr", "192[dot]168[dot]1[dot]1", "192.168.1.1", id="ipv4 [dot]"
    ),
    pytest.param("ipv4-addr", "10[.]0[.]0[.]0[/]8", "10.0.0.0/8", id="ipv4 [/]"),
    pytest.param("ipv6-addr", "2001[:]db8[:][:]1", "2001:db8::1", id="ipv6 [:]"),
    pytest.param("ipv6-addr", "2001(:)db8(:)(:)1", "2001:db8::1", id="ipv6 (:)"),
    pytest.param("ipv6-addr", "2001[:]db8[:][:][/]32", "2001:db8::/32", id="ipv6 [/]"),
    pytest.param(
        "ipv6-addr", "::ffff[:]192[.]0[.]2[.]1", "::ffff:192.0.2.1", id="ipv6 mapped"
    ),
    pytest.param(
        "url", "hxxp://filigran[.]io/about", "http://filigran.io/about", id="hxxp"
    ),
    pytest.param("url", "hxxps://filigran[.]io", "https://filigran.io", id="hxxps"),
    pytest.param("url", "HXXPS://filigran[.]io", "https://filigran.io", id="HXXPS"),
    pytest.param("url", "hXXp://filigran[.]io", "http://filigran.io", id="hXXp"),
    pytest.param(
        "url", "fxp://files[.]filigran[.]io/x", "ftp://files.filigran.io/x", id="fxp"
    ),
    pytest.param("url", "https[:]//filigran[.]io", "https://filigran.io", id="[:]"),
    pytest.param("url", "https[://]filigran[.]io", "https://filigran.io", id="[://]"),
    pytest.param(
        "url", "hxxps://filigran[.]io[/]about", "https://filigran.io/about", id="[/]"
    ),
    pytest.param(
        "url",
        "hxxps://filigran[.]io[:]8443/login",
        "https://filigran.io:8443/login",
        id="url port",
    ),
    pytest.param(
        "url",
        "hxxp://admin[at]filigran[.]io/",
        "http://admin@filigran.io/",
        id="url userinfo",
    ),
    pytest.param(
        "url",
        "mailto:admin[at]filigran[dot]io",
        "mailto:admin@filigran.io",
        id="url embedded email",
    ),
    pytest.param(
        "url", "filigran[.]io/about", "filigran.io/about", id="url without scheme"
    ),
]

CLEAN_VALUES = [
    ("domain-name", "filigran.io"),
    ("domain-name", "at.dot.filigran.io"),
    ("hostname", "srv01.filigran.io"),
    ("email-addr", "admin@filigran.io"),
    ("email-addr", "first.last+tag@filigran.io"),
    ("ipv4-addr", "192.168.1.1"),
    ("ipv4-addr", "10.0.0.0/8"),
    ("ipv6-addr", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("ipv6-addr", "::1"),
    ("url", "https://filigran.io/about?q=a.b#top"),
    ("url", "http://[2001:db8::1]:8080/index.html"),
    ("url", "https://en.wikipedia.org/wiki/Mercury_(planet)"),
]

UNREFANGABLE_VALUES = [
    pytest.param("email-addr", "admin[at][dot]io", id="email without domain"),
    pytest.param("email-addr", "admin[at]filigran[:]io", id="colon in an email"),
    pytest.param("domain-name", "evil[at]example[.]com", id="at in a domain name"),
    pytest.param("domain-name", "filigran[.]i", id="one-letter tld"),
    pytest.param("hostname", "srv01[.]", id="hostname trailing dot"),
    pytest.param("ipv4-addr", "999[.]1[.]1[.]1", id="ipv4 out of range"),
    pytest.param("ipv6-addr", "2001[:]zz[:][:]1", id="ipv6 not hexadecimal"),
    pytest.param("url", "hxxp://filigran [dot io/", id="url unbalanced notation"),
    pytest.param("url", "hxxp[://]", id="url without host"),
    pytest.param("url", "hxxp://[:]8080/", id="url port without host"),
    pytest.param("url", "hxxp://filigran[.]io[:]https/", id="url non-numeric port"),
    pytest.param("url", "hxxp://[2001[:]db8[:][:]1/", id="url unbalanced ipv6 host"),
]

OBSERVABLE_CLASSES = {
    "domain-name": stix2.DomainName,
    "email-addr": stix2.EmailAddress,
    "hostname": pycti.CustomObservableHostname,
    "ipv4-addr": stix2.IPv4Address,
    "ipv6-addr": stix2.IPv6Address,
    "url": stix2.URL,
}


def observable(observable_type: str, value: str, **properties) -> dict:
    """An observable as the extraction returns it, its id derived from its value."""
    return json.loads(
        stix2.parse(
            {
                "type": observable_type,
                "spec_version": "2.1",
                "value": value,
                **properties,
            },
            allow_custom=True,
        ).serialize()
    )


def intrusion_set(name: str) -> dict:
    return {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": pycti.IntrusionSet.generate_id(name),
        "name": name,
    }


def relationship(relationship_type: str, source_ref: str, target_ref: str) -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }


def report(object_refs: list[str], **properties) -> dict:
    published = "2026-09-01T00:00:00.000Z"
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": pycti.Report.generate_id("Defanged report", published),
        "name": "Defanged report",
        "published": published,
        "report_types": ["threat-report"],
        "object_refs": object_refs,
        **properties,
    }


def make_bundle(*objects: dict) -> stix2.Bundle:
    return stix2.Bundle(
        type="bundle",
        id=f"bundle--{uuid.uuid4()}",
        objects=list(objects),
        allow_custom=True,
    )


def serialized_objects(bundle: stix2.Bundle) -> list[dict]:
    return json.loads(bundle.serialize())["objects"]


def object_with_id(bundle: stix2.Bundle, object_id: str) -> dict:
    return next(obj for obj in serialized_objects(bundle) if obj["id"] == object_id)


def references(value: object, name: str | None = None) -> list[str]:
    """Every id held by a ``*_ref`` / ``*_refs`` property, at any depth."""
    if isinstance(value, dict):
        return [
            ref
            for item_name, item in value.items()
            for ref in references(item, item_name)
        ]
    if isinstance(value, list):
        return [ref for item in value for ref in references(item, name)]
    if isinstance(value, str) and name and name.endswith(("_ref", "_refs")):
        return [value]
    return []


def dangling_references(bundle: stix2.Bundle) -> set[str]:
    objects = serialized_objects(bundle)
    object_ids = {obj["id"] for obj in objects}
    return {
        ref
        for ref in references(objects)
        if ref not in object_ids and not ref.startswith("marking-definition--")
    }


@pytest.mark.parametrize(
    "observable_type, value, expected",
    [
        pytest.param("email-addr", ISSUE_EMAIL, "admin@filigran.io", id="email"),
        pytest.param(
            "ipv6-addr",
            ISSUE_IPV6,
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            id="ipv6",
        ),
    ],
)
def test_refang_the_values_of_the_issue(observable_type, value, expected):
    # Given the defanged values reported in XTM-One-Platform/xtm-one#2665
    # When refanging them
    # Then they become the values OpenCTI accepts
    assert refang_observable_value(observable_type, value) == expected


@pytest.mark.parametrize("observable_type, value, expected", NOTATIONS)
def test_refang_each_notation(observable_type, value, expected):
    # Given a value defanged with one of the common notations
    # When refanging it, then the notation is replaced by its separator
    assert refang_observable_value(observable_type, value) == expected


@pytest.mark.parametrize("observable_type, value, expected", NOTATIONS)
def test_refanging_is_idempotent(observable_type, value, expected):
    # Given an already refanged value
    # When refanging it again, then it is left unchanged
    refanged = refang_observable_value(observable_type, value)
    assert refang_observable_value(observable_type, refanged) == refanged


@pytest.mark.parametrize("observable_type, value", CLEAN_VALUES)
def test_clean_values_are_left_unchanged(observable_type, value):
    # Given a value that is not defanged, including look-alikes such as a
    # bracketed IPv6 host or a parenthesised path segment
    # When refanging it, then it is returned as is
    assert refang_observable_value(observable_type, value) == value


@pytest.mark.parametrize("observable_type, value", UNREFANGABLE_VALUES)
def test_values_that_do_not_refang_into_a_valid_value_are_left_unchanged(
    observable_type, value
):
    # Given a defanged value that is not a valid value of its type once
    # refanged (or holds a notation its type cannot hold)
    # When refanging it, then no value is invented: it is returned as is
    assert refang_observable_value(observable_type, value) == value


@pytest.mark.parametrize(
    "observable_type, value",
    [
        ("file", "invoice[.]pdf[.]exe"),
        ("mac-addr", "00[:]11[:]22[:]33[:]44[:]55"),
        ("text", ISSUE_EMAIL),
    ],
)
def test_other_observable_types_are_left_unchanged(observable_type, value):
    # Given a value of a type that is not a network indicator
    # When refanging it, then it is returned as is
    assert refang_observable_value(observable_type, value) == value


@pytest.mark.parametrize("observable_type, value, expected", NOTATIONS)
def test_refanged_observables_get_the_id_stix2_derives_from_their_value(
    observable_type, value, expected
):
    # Given an observable whose id derives from its defanged value
    defanged = observable(observable_type, value, defanged=True)
    bundle = make_bundle(defanged)

    # When refanging the bundle
    refanged_bundle, summary = refang_bundle_observables(bundle)

    # Then the observable holds the refanged value, the id stix2 derives from
    # it, and no longer claims to be defanged
    expected_id = OBSERVABLE_CLASSES[observable_type](value=expected)["id"]
    assert serialized_objects(refanged_bundle) == [
        {
            "type": observable_type,
            "spec_version": "2.1",
            "id": expected_id,
            "value": expected,
        }
    ]
    assert summary.refanged == [
        RefangedObservable(
            observable_type=observable_type,
            original_id=defanged["id"],
            original_value=value,
            refanged_id=expected_id,
            refanged_value=expected,
        )
    ]
    assert summary.unrefanged == []
    assert summary.merged_objects == 0


def test_every_reference_to_a_refanged_observable_is_rewritten():
    # Given a bundle referencing defanged observables from a report, a
    # relationship, a domain name, an email message and an object of a type
    # stix2 does not know
    email = observable("email-addr", ISSUE_EMAIL, defanged=True)
    ipv6 = observable("ipv6-addr", ISSUE_IPV6, defanged=True)
    ipv4 = observable("ipv4-addr", "198[.]51[.]100[.]7")
    domain = observable("domain-name", "filigran.io", resolves_to_refs=[ipv4["id"]])
    message = json.loads(
        stix2.parse(
            {
                "type": "email-message",
                "spec_version": "2.1",
                "is_multipart": False,
                "from_ref": email["id"],
                "to_refs": [email["id"]],
                "subject": "Mail from admin[at]filigran[dot]io",
            },
            allow_custom=True,
        ).serialize()
    )
    apt = intrusion_set("APT41")
    uses = relationship("related-to", apt["id"], email["id"])
    unknown_type = {
        "type": "x-acme-alert",
        "spec_version": "2.1",
        "id": f"x-acme-alert--{uuid.uuid4()}",
        "x_acme_observable_ref": ipv6["id"],
    }
    container = report(
        [
            email["id"],
            ipv6["id"],
            ipv4["id"],
            domain["id"],
            message["id"],
            apt["id"],
            uses["id"],
        ]
    )
    bundle = make_bundle(
        email, ipv6, ipv4, domain, message, apt, uses, unknown_type, container
    )

    # When refanging the bundle
    refanged_bundle, _ = refang_bundle_observables(bundle)

    # Then no object references a former id any more and every reference
    # resolves to an object of the bundle
    email_id = stix2.EmailAddress(value="admin@filigran.io")["id"]
    ipv6_id = stix2.IPv6Address(value="2001:0db8:85a3:0000:0000:8a2e:0370:7334")["id"]
    ipv4_id = stix2.IPv4Address(value="198.51.100.7")["id"]
    serialized = refanged_bundle.serialize()
    for former_id in (email["id"], ipv6["id"], ipv4["id"]):
        assert former_id not in serialized
    assert dangling_references(refanged_bundle) == set()
    assert object_with_id(refanged_bundle, container["id"])["object_refs"] == [
        email_id,
        ipv6_id,
        ipv4_id,
        domain["id"],
        message["id"],
        apt["id"],
        uses["id"],
    ]
    assert object_with_id(refanged_bundle, uses["id"])["target_ref"] == email_id
    assert object_with_id(refanged_bundle, domain["id"])["resolves_to_refs"] == [
        ipv4_id
    ]
    refanged_message = object_with_id(refanged_bundle, message["id"])
    assert refanged_message["from_ref"] == email_id
    assert refanged_message["to_refs"] == [email_id]
    assert refanged_message["subject"] == "Mail from admin[at]filigran[dot]io"
    assert object_with_id(refanged_bundle, unknown_type["id"]) == {
        **unknown_type,
        "x_acme_observable_ref": ipv6_id,
    }


def test_spellings_of_a_same_value_are_merged_into_one_observable():
    # Given two spellings of one address plus its clean form, each with its
    # own properties, all referenced by the report
    tlp_green = stix2.TLP_GREEN["id"]
    tlp_amber = stix2.TLP_AMBER["id"]
    bracketed = observable(
        "email-addr",
        ISSUE_EMAIL,
        defanged=True,
        object_marking_refs=[tlp_green],
        x_opencti_score=50,
    )
    parenthesised = observable(
        "email-addr",
        "admin(at)filigran(.)io",
        defanged=True,
        object_marking_refs=[tlp_amber],
        x_opencti_score=80,
    )
    clean = observable(
        "email-addr",
        "admin@filigran.io",
        object_marking_refs=[tlp_green],
        x_opencti_description="Administrator mailbox",
    )
    container = report([bracketed["id"], parenthesised["id"], clean["id"]])
    bundle = make_bundle(bracketed, parenthesised, clean, container)

    # When refanging the bundle
    refanged_bundle, summary = refang_bundle_observables(bundle)

    # Then a single observable remains, in the first spelling's place, with
    # the first spelling's values and the properties of the others
    email_id = clean["id"]
    assert [obj["id"] for obj in serialized_objects(refanged_bundle)] == [
        email_id,
        container["id"],
    ]
    assert object_with_id(refanged_bundle, email_id) == {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": email_id,
        "value": "admin@filigran.io",
        "object_marking_refs": [tlp_green, tlp_amber],
        "x_opencti_description": "Administrator mailbox",
        "x_opencti_score": 50,
    }
    assert object_with_id(refanged_bundle, container["id"])["object_refs"] == [email_id]
    assert summary.merged_objects == 2
    assert [item.refanged_id for item in summary.refanged] == [email_id, email_id]


def test_relationships_made_identical_by_a_merge_are_merged():
    # Given an intrusion set related to two spellings of one address, and two
    # identical relationships the refang does not touch
    apt = intrusion_set("APT41")
    bracketed = observable("email-addr", ISSUE_EMAIL)
    parenthesised = observable("email-addr", "admin(at)filigran(.)io")
    ipv4 = observable("ipv4-addr", "198.51.100.7")
    first = relationship("related-to", apt["id"], bracketed["id"])
    second = relationship("related-to", apt["id"], parenthesised["id"])
    untouched = relationship("related-to", apt["id"], ipv4["id"])
    untouched_twin = relationship("related-to", apt["id"], ipv4["id"])
    container = report(
        [
            apt["id"],
            bracketed["id"],
            parenthesised["id"],
            ipv4["id"],
            first["id"],
            second["id"],
            untouched["id"],
            untouched_twin["id"],
        ]
    )
    bundle = make_bundle(
        apt,
        bracketed,
        parenthesised,
        ipv4,
        first,
        second,
        untouched,
        untouched_twin,
        container,
    )

    # When refanging the bundle
    refanged_bundle, summary = refang_bundle_observables(bundle)

    # Then the two relationships to the merged address are one, the report
    # follows, and the relationships the refang did not touch are kept
    email_id = stix2.EmailAddress(value="admin@filigran.io")["id"]
    assert [obj["id"] for obj in serialized_objects(refanged_bundle)] == [
        apt["id"],
        email_id,
        ipv4["id"],
        first["id"],
        untouched["id"],
        untouched_twin["id"],
        container["id"],
    ]
    assert object_with_id(refanged_bundle, first["id"])["target_ref"] == email_id
    assert object_with_id(refanged_bundle, container["id"])["object_refs"] == [
        apt["id"],
        email_id,
        ipv4["id"],
        first["id"],
        untouched["id"],
        untouched_twin["id"],
    ]
    assert dangling_references(refanged_bundle) == set()
    assert summary.merged_objects == 2


def test_values_that_do_not_refang_into_a_valid_value_are_sent_unchanged():
    # Given a defanged address that is not an address once refanged
    email = observable("email-addr", "admin[at][dot]io", defanged=True)
    container = report([email["id"]])
    bundle = make_bundle(email, container)

    # When refanging the bundle
    refanged_bundle, summary = refang_bundle_observables(bundle)

    # Then the bundle is left untouched for OpenCTI to report the value, and
    # the value is reported as not refanged
    assert refanged_bundle is bundle
    assert summary.refanged == []
    assert summary.unrefanged == [
        UnrefangedObservable("email-addr", email["id"], "admin[at][dot]io")
    ]


def test_free_text_keeps_its_defanged_spelling():
    # Given defanged indicators quoted in names, descriptions and external
    # references, next to a defanged URL observable
    url = observable(
        "url",
        "hxxps://evil[.]com/payload",
        x_opencti_description="Served by hxxps://evil[.]com",
    )
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": pycti.Malware.generate_id("admin[at]filigran[dot]io dropper"),
        "name": "admin[at]filigran[dot]io dropper",
        "description": "Beacons to hxxps://evil[.]com",
        "is_family": False,
    }
    container = report(
        [url["id"], malware["id"]],
        description="Mails admin[at]filigran[dot]io from evil[.]com",
        external_references=[
            {"source_name": "vendor", "url": "hxxps://vendor[.]com/report"}
        ],
    )
    bundle = make_bundle(url, malware, container)

    # When refanging the bundle
    refanged_bundle, _ = refang_bundle_observables(bundle)

    # Then only the observable value is refanged
    url_id = stix2.URL(value="https://evil.com/payload")["id"]
    assert object_with_id(refanged_bundle, url_id) == {
        **object_with_id(bundle, url["id"]),
        "id": url_id,
        "value": "https://evil.com/payload",
    }
    assert object_with_id(refanged_bundle, malware["id"]) == object_with_id(
        bundle, malware["id"]
    )
    assert object_with_id(refanged_bundle, container["id"]) == {
        **object_with_id(bundle, container["id"]),
        "object_refs": [url_id, malware["id"]],
    }


def test_bundle_without_defanged_observables_is_returned_as_is():
    # Given a bundle whose observables are clean
    email = observable("email-addr", "admin@filigran.io")
    bundle = make_bundle(email, report([email["id"]]))

    # When refanging the bundle, then the very same bundle is returned
    refanged_bundle, summary = refang_bundle_observables(bundle)

    assert refanged_bundle is bundle
    assert summary.refanged == []
    assert summary.unrefanged == []


def test_refanging_a_bundle_is_idempotent():
    # Given a refanged bundle
    email = observable("email-addr", ISSUE_EMAIL, defanged=True)
    ipv6 = observable("ipv6-addr", ISSUE_IPV6)
    refanged_bundle, _ = refang_bundle_observables(
        make_bundle(email, ipv6, report([email["id"], ipv6["id"]]))
    )

    # When refanging it again, then nothing changes
    refanged_twice, summary = refang_bundle_observables(refanged_bundle)

    assert refanged_twice is refanged_bundle
    assert summary.refanged == []
