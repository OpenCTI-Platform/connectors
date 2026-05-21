import uuid
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import urlparse

import stix2
from lib.actor_typing import infer_actor_entity_type
from pycti import CustomObservableCryptographicKey as CryptoKey
from pycti import CustomObservablePhoneNumber as PhoneNumber
from pycti import IntrusionSet as PyctiIntrusionSet
from pycti import ThreatActorGroup as PyctiTAG
from pycti.entities.opencti_identity import Identity as PyctiIdentity
from pycti.entities.opencti_indicator import Indicator as PyctiIndicator
from pycti.entities.opencti_location import Location as PyctiLocation
from pycti.entities.opencti_malware import Malware as PyctiMalware
from pycti.entities.opencti_stix_core_relationship import (
    StixCoreRelationship as PyctiSCR,
)
from pycti.entities.opencti_threat_actor_individual import (
    ThreatActorIndividual as PyctiTAI,
)
from pycti.entities.opencti_vulnerability import Vulnerability as PyctiVulnerability
from stix2.canonicalization.Canonicalize import canonicalize

# ``pycti`` ships pre-registered ``CustomObservableCryptographicKey`` and
# ``CustomObservablePhoneNumber`` classes (see ``pycti/__init__.py``).
# The original version of this connector re-declared them through
# ``@CustomObservable(...)``, which raised ``DuplicateRegistrationError``
# at import time on any modern ``pycti`` and prevented the connector
# from ever starting. The pre-registered classes only declare the
# STIX-required core properties (``id``, ``value``, ``object_marking_refs``,
# ...), so we carry the connector-specific extras (``description``,
# ``x_opencti_created_by_ref``) through ``custom_properties`` with
# ``allow_custom=True`` instead — same pattern as
# ``pycti.CustomObservableMediaContent`` is consumed in ``main.py``.
#
# OpenCTI carries the observable author through ``x_opencti_created_by_ref``
# (see ``connectors-sdk/connectors_sdk/models/base_observable_entity.py``),
# not the STIX-standard ``created_by_ref`` which only applies to SDOs.


def generate_observable_id(value, observable):
    data = {"value": value}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return observable + "--" + id


def generate_file_id(name, sha256, sha1, md5):
    data = {
        "name": name.lower().strip(),
        "hashes": {
            "SHA-256": sha256.lower().strip(),
            "SHA-1": sha1.lower().strip(),
            "MD5": md5.lower().strip(),
        },
    }
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "file--" + id


def generate_user_account_id(user_id):
    data = {"user_id": user_id}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "user-account--" + id


def get_date(octi_date) -> str:
    d = octi_date.rstrip("Z").split("T")
    return d[0] + " " + d[1]


def sanitizeName(name) -> str:
    result = name
    if len(name) < 2:
        result += "="
    return result


def _escape_stix_pattern_value(value: str) -> str:
    """Escape ``value`` for inclusion inside a single-quoted STIX pattern.

    STIX 2.1 patterns use single-quoted string literals; per the spec the
    backslash itself and the single quote both have to be escaped (``\\\\``
    and ``\\'``) so the resulting pattern is well-formed and is interpreted
    as a literal value rather than a syntactic terminator.

    Intel 471 URL payloads can legitimately contain single quotes (and
    sometimes backslashes) and used to be embedded verbatim, which made
    ``stix2.Indicator`` reject the pattern or, worse, silently change its
    meaning. Callers building patterns of the form
    ``[url:value='<value>']`` must therefore pre-process the value with
    this helper.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def getMotivation(codelist) -> str:
    result = ""
    for item in codelist:
        if item == "CC":
            result += "Cyber Crime\n\n"
        elif item == "CE":
            result += "Cyber Espionage\n\n"
        elif item == "HA":
            result += "Hacktivism\n\n"
        else:
            result += item + "\n\n"
    return result


def getBreachConfidence(confidence: str) -> int:
    result = 0
    match confidence:
        case "low":
            result = 15
        case "medium":
            result = 50
        case "high":
            result = 85
    return result


def getAdmiralty(code) -> ():
    reliability = code[0]
    credibility = code[1]
    r = c = None
    match reliability:
        case "A":
            r = "A - Completely reliable"
        case "B":
            r = "B - Usually reliable"
        case "C":
            r = "C - Fairly reliable"
        case "D":
            r = "D - Not usually reliable"
        case "E":
            r = "E - Unreliable"
        case "F":
            r = "F - Reliability cannot be judged"
    match credibility:
        case "1":
            c = 90
        case "2":
            c = 70
        case "3":
            c = 50
        case "4":
            c = 30
        case "5":
            c = 10
        case "6":
            c = 0
    return (r, c)


def getThreatActorContent(
    actor: dict,
    markings,
    creator,
    description: str = "",
    external_references: list[dict] | None = None,
):
    """
    Transforms an Intel471 actor dictionnary into a STIX SDO using inferred
    OpenCTI entity typing.
    """
    result = None
    # in case of a report alert
    if "handle" in actor:
        x_aliases = actor["aliases"] if "aliases" in actor else []
        x_name = actor["handle"]
        x_ext_refs = external_references or []
        entity_type = infer_actor_entity_type(actor)
        if entity_type == "Intrusion-Set":
            result = stix2.IntrusionSet(
                id=PyctiIntrusionSet.generate_id(x_name),
                name=x_name,
                description=description,
                aliases=x_aliases,
                created_by_ref=creator,
                external_references=x_ext_refs,
                object_marking_refs=markings,
            )
        elif entity_type == "Threat-Actor-Group":
            result = stix2.ThreatActor(
                id=PyctiTAG.generate_id(x_name),
                name=x_name,
                description=description,
                aliases=x_aliases,
                created_by_ref=creator,
                external_references=x_ext_refs,
                custom_properties={"x_opencti_type": "Threat-Actor-Group"},
                object_marking_refs=markings,
            )
        elif entity_type == "Malware":
            result = stix2.Malware(
                id=PyctiMalware.generate_id(x_name),
                name=x_name,
                is_family=True,
                description=description,
                aliases=x_aliases,
                created_by_ref=creator,
                external_references=x_ext_refs,
                object_marking_refs=markings,
            )
        else:
            result = stix2.ThreatActor(
                id=PyctiTAI.generate_id(x_name),
                name=x_name,
                description=description,
                aliases=x_aliases,
                created_by_ref=creator,
                external_references=x_ext_refs,
                custom_properties={"x_opencti_type": "Threat-Actor-Individual"},
                object_marking_refs=markings,
            )
    return result


def getVictimContent(victim: dict, markings, creator) -> stix2.Identity:
    """
    Transforms an Intel471 victim dictionnary into a STIX Identity object.
    """
    x_ext_refs = []
    if "urls" in victim:
        for u in victim["urls"]:
            x_ext_refs.append({"source_name": victim["name"], "url": u})
    return stix2.Identity(
        id=PyctiIdentity.generate_id(sanitizeName(victim["name"]), "organization"),
        name=sanitizeName(victim["name"]),
        external_references=x_ext_refs,
        identity_class="organization",
        created_by_ref=creator,
        object_marking_refs=markings,
    )


def getIndustriesContent(industry: dict, markings, creator) -> ():
    subsector = stix2.Identity(
        id=PyctiIdentity.generate_id(sanitizeName(industry["industry"]), "class"),
        name=industry["industry"],
        identity_class="class",
        created_by_ref=creator,
        custom_properties={"x_opencti_type": "Sector"},
        object_marking_refs=markings,
    )
    sector = stix2.Identity(
        id=PyctiIdentity.generate_id(sanitizeName(industry["sector"]), "class"),
        name=industry["sector"],
        identity_class="class",
        created_by_ref=creator,
        custom_properties={"x_opencti_type": "Sector"},
        object_marking_refs=markings,
    )
    return (subsector, sector)


def getLocationContent(location: dict, markings, creator):
    """
    Transforms an Intel471 location dictionary into a tuple containing
    - a STIX Location object
    - a string describing the relationship to the threat actor

    Returns ``None`` when neither ``region`` nor ``country`` is present so the
    caller can skip creating an empty/invalid Location object.
    """
    x_region = location.get("region")
    x_country = location.get("country")
    if not x_region and not x_country:
        return None
    if x_region and x_country:
        loc = stix2.Location(
            id=PyctiLocation.generate_id(x_country, "country", None, None),
            region=x_region,
            country=x_country,
            created_by_ref=creator,
            object_marking_refs=markings,
        )
    elif x_region:
        loc = stix2.Location(
            id=PyctiLocation.generate_id(x_region, "region", None, None),
            region=x_region,
            created_by_ref=creator,
            object_marking_refs=markings,
        )
    else:  # x_country only
        loc = stix2.Location(
            id=PyctiLocation.generate_id(x_country, "country", None, None),
            country=x_country,
            created_by_ref=creator,
            object_marking_refs=markings,
        )
    link_value = location.get("link")
    if link_value == "impacts":
        rel = "targets"
    elif link_value == "active_in":
        rel = "located-at"
    elif link_value:
        rel = link_value
    else:
        rel = "located-at"
    return (rel, loc)


def getTypeValueContent(entity: dict, markings, creator) -> ():
    """
    Transforms an Intel471 entity or contact information dictionnary into a tuple containing:
    - a string describing the type of content: Object, ExtRef or Label
    - the OpenCTI STIX content: a list of Objects OR an external referencei dictionnary OR a label string
    """
    result = ()
    match entity["type"]:

        # case "BitcoinAddress" | "OtherCryptCurrencies" | "QiwiWallet":
        #    result = ("Object", CryptoWallet(value=entity["value"], description=entity["type"]))

        case "FileName" | "FileSize" | "FileType":
            result = (
                "Object",
                [
                    stix2.File(
                        id=generate_file_id(entity["value"], "", "", ""),
                        name=entity["value"],
                        custom_properties={
                            "x_opencti_description": entity["type"],
                            "x_opencti_created_by_ref": creator,
                        },
                        object_marking_refs=markings,
                    )
                ],
            )

        case (
            "PGPKey"
            | "PGPKeyID"
            | "SSLCertificate"
            | "SSLCertificateID"
            | "SSLCertificateFingerprint"
        ):
            result = (
                "Object",
                [
                    CryptoKey(
                        id=generate_observable_id(entity["value"], "cryptographic-key"),
                        value=entity["value"],
                        object_marking_refs=markings,
                        allow_custom=True,
                        custom_properties={
                            "x_opencti_description": entity["type"],
                            "x_opencti_created_by_ref": creator,
                        },
                    )
                ],
            )

        case (
            "Discord"
            | "GitHub"
            | "Jabber"
            | "AIM"
            | "ICQ"
            | "Instagram"
            | "LinkedIn"
            | "MSN"
            | "MoiMir"
            | "Odnoklassniki"
            | "PerfectMoneyID"
            | "QQ"
            | "Telegram"
            | "Tox"
            | "VK"
            | "WeChat"
            | "WebMoneyID"
            | "WebMoneyPurse"
            | "Wickr"
            | "YahooIM"
            | "YandexMoney"
        ):
            result = (
                "Object",
                [
                    stix2.UserAccount(
                        id=generate_observable_id(entity["value"], "user-account"),
                        user_id=entity["value"],
                        custom_properties={
                            "x_opencti_description": entity["type"],
                            "x_opencti_created_by_ref": creator,
                        },
                        object_marking_refs=markings,
                    )
                ],
            )

        case "Facebook" | "Skype" | "Twitter":
            result = (
                "Object",
                [
                    stix2.UserAccount(
                        id=generate_observable_id(entity["value"], "user-account"),
                        user_id=entity["value"],
                        account_type=entity["type"].lower(),
                        custom_properties={"x_opencti_created_by_ref": creator},
                        object_marking_refs=markings,
                    )
                ],
            )

        case "ActorDomain" | "MaliciousDomain":
            # ``str.lstrip`` strips *characters* in its argument, not a prefix,
            # so the previous loop only worked by accident. ``urlparse`` returns
            # ``netloc`` for inputs that contain a scheme and reuses ``path``
            # for bare hostnames, so ``netloc or path`` gives us the host part
            # in both cases.
            raw_domain = (entity["value"] or "").strip()
            parsed = urlparse(raw_domain if "://" in raw_domain else f"//{raw_domain}")
            d = (parsed.hostname or parsed.path or raw_domain).strip().lower()
            observable = stix2.DomainName(
                id=generate_observable_id(d, "domain-name"),
                value=d,
                custom_properties={
                    "x_opencti_description": entity["type"],
                    "x_opencti_created_by_ref": creator,
                },
                object_marking_refs=markings,
            )
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(f"[domain-name:value='{d}']"),
                pattern=f"[domain-name:value='{d}']",
                pattern_type="stix",
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "EmailAddress":
            result = (
                "Object",
                [
                    stix2.EmailAddress(
                        id=generate_observable_id(entity["value"], "email-addr"),
                        value=entity["value"],
                        custom_properties={
                            "x_opencti_description": entity["type"],
                            "x_opencti_created_by_ref": creator,
                        },
                        object_marking_refs=markings,
                    )
                ],
            )

        case "Handle":
            result = (
                "Object",
                [
                    stix2.Identity(
                        id=PyctiIdentity.generate_id(entity["value"], "individual"),
                        name=entity["value"],
                        identity_class="individual",
                        created_by_ref=creator,
                        object_marking_refs=markings,
                    )
                ],
            )

        case "IPv4Prefix":
            ip = entity["value"]
            observable = stix2.IPv4Address(
                id=generate_observable_id(ip, "ipv4-addr"),
                value=ip,
                custom_properties={
                    "x_opencti_description": entity["type"],
                    "x_opencti_created_by_ref": creator,
                },
                object_marking_refs=markings,
            )
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(f"[ipv4-addr:value='{ip}']"),
                pattern=f"[ipv4-addr:value='{ip}']",
                pattern_type="stix",
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "IPv6Prefix":
            ip = entity["value"]
            observable = stix2.IPv6Address(
                id=generate_observable_id(ip, "ipv6-addr"),
                value=ip,
                custom_properties={
                    "x_opencti_description": entity["type"],
                    "x_opencti_created_by_ref": creator,
                },
                object_marking_refs=markings,
            )
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(f"[ipv6-addr:value='{ip}']"),
                pattern=f"[ipv6-addr:value='{ip}']",
                pattern_type="stix",
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "IPAddress":
            observable = None
            indicator = None
            ip = entity["value"]
            if type(ip_address(ip)) is IPv4Address:
                observable = stix2.IPv4Address(
                    id=generate_observable_id(ip, "ipv4-addr"),
                    value=ip,
                    custom_properties={
                        "x_opencti_description": entity["type"],
                        "x_opencti_created_by_ref": creator,
                    },
                    object_marking_refs=markings,
                )
                indicator = stix2.Indicator(
                    id=PyctiIndicator.generate_id(f"[ipv4-addr:value='{ip}']"),
                    pattern=f"[ipv4-addr:value='{ip}']",
                    pattern_type="stix",
                    created_by_ref=creator,
                    object_marking_refs=markings,
                )
            if type(ip_address(ip)) is IPv6Address:
                observable = stix2.IPv6Address(
                    id=generate_observable_id(ip, "ipv6-addr"),
                    value=ip,
                    custom_properties={
                        "x_opencti_description": entity["type"],
                        "x_opencti_created_by_ref": creator,
                    },
                    object_marking_refs=markings,
                )
                indicator = stix2.Indicator(
                    id=PyctiIndicator.generate_id(f"[ipv6-addr:value='{ip}']"),
                    pattern=f"[ipv6-addr:value='{ip}']",
                    pattern_type="stix",
                    created_by_ref=creator,
                    object_marking_refs=markings,
                )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "MalwareFamily" | "MobileMalwareFamily":
            result = (
                "Object",
                [
                    stix2.Malware(
                        id=PyctiMalware.generate_id(entity["value"]),
                        name=entity["value"],
                        is_family=True,
                        created_by_ref=creator,
                        object_marking_refs=markings,
                    )
                ],
            )

        case "Phone":
            result = (
                "Object",
                [
                    PhoneNumber(
                        id=generate_observable_id(entity["value"], "phone-number"),
                        value=entity["value"],
                        object_marking_refs=markings,
                        allow_custom=True,
                        custom_properties={
                            "x_opencti_created_by_ref": creator,
                        },
                    )
                ],
            )

        case "ActorOtherWebsite" | "MaliciousURL" | "URL":
            url = entity["value"]
            observable = stix2.URL(
                id=generate_observable_id(url, "url"),
                value=url,
                custom_properties={"x_opencti_created_by_ref": creator},
                object_marking_refs=markings,
            )
            # Intel 471 URLs can legitimately contain single quotes and
            # backslashes; both must be escaped before being embedded in
            # a single-quoted STIX pattern, otherwise ``stix2.Indicator``
            # either rejects the pattern outright or silently changes
            # its meaning.
            url_pattern = f"[url:value='{_escape_stix_pattern_value(url)}']"
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(url_pattern),
                pattern=url_pattern,
                pattern_type="stix",
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "MD5":
            h = entity["value"]
            observable = stix2.File(
                id=generate_file_id("", "", "", h),
                hashes={"MD5": h},
                custom_properties={"x_opencti_created_by_ref": creator},
                object_marking_refs=markings,
            )
            pattern = f"[file:hashes.'MD5' = '{h}']"
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(pattern),
                pattern=pattern,
                pattern_type="stix",
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "SHA1":
            h = entity["value"]
            observable = stix2.File(
                id=generate_file_id("", "", h, ""),
                hashes={"SHA-1": h},
                custom_properties={"x_opencti_created_by_ref": creator},
                object_marking_refs=markings,
            )
            pattern = f"[file:hashes.'SHA-1' = '{h}']"
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(pattern),
                pattern=pattern,
                pattern_type="stix",
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "SHA256":
            h = entity["value"]
            observable = stix2.File(
                id=generate_file_id("", h, "", ""),
                hashes={"SHA-256": h},
                custom_properties={"x_opencti_created_by_ref": creator},
                object_marking_refs=markings,
            )
            pattern = f"[file:hashes.'SHA-256' = '{h}']"
            indicator = stix2.Indicator(
                id=PyctiIndicator.generate_id(pattern),
                pattern=pattern,
                pattern_type="stix",
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            relationship = stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "based-on", indicator["id"], observable["id"], None, None
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=creator,
                object_marking_refs=markings,
            )
            result = ("Object", [observable, indicator, relationship])

        case "CveID":
            result = (
                "Object",
                [
                    stix2.Vulnerability(
                        id=PyctiVulnerability.generate_id(entity["value"]),
                        name=entity["value"],
                        created_by_ref=creator,
                        object_marking_refs=markings,
                    )
                ],
            )

        case "AutonomousSystem":
            result = (
                "Object",
                [
                    stix2.AutonomousSystem(
                        id=generate_observable_id(
                            entity["value"].lstrip("AS"), "autonomous-system"
                        ),
                        number=int(entity["value"].lstrip("AS")),
                        custom_properties={"x_opencti_created_by_ref": creator},
                        object_marking_refs=markings,
                    )
                ],
            )

        case "BitcoinTransactionID":
            result = (
                "ExtRef",
                {"source_name": entity["type"], "external_id": entity["value"]},
            )

        case "Tag":
            result = ("Label", entity["value"])

    return result
