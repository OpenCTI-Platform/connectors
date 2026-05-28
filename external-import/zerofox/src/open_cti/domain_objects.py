import pycountry
import pycti
from stix2 import (
    TLP_AMBER,
    ExternalReference,
    Indicator,
    Infrastructure,
    Location,
    Malware,
    Relationship,
    Tool,
    Vulnerability,
)


def _get_country_name(country_code: str) -> str:
    try:
        return pycountry.countries.get(alpha_2=country_code).name
    except Exception:
        return country_code


def _additional_kwargs(created_by) -> dict:
    return {
        "created_by_ref": created_by,
        "object_marking_refs": [TLP_AMBER.id],
    }


def indicator(
    name: str,
    created_by: str,
    valid_from,
    pattern: str,
    pattern_type: str,
    indicator_types: list,
    observable_type: str,
):
    return Indicator(
        id=pycti.Indicator.generate_id(pattern=pattern),
        name=name,
        valid_from=valid_from,
        pattern=pattern,
        pattern_type=pattern_type,
        indicator_types=indicator_types,
        **_additional_kwargs(created_by),
        custom_properties={
            "x_opencti_main_observable_type": observable_type,
        },
    )


def infrastructure(
    created_by: str,
    name: str,
    infrastructure_types: str,
    created: str | None = None,
    first_seen=None,
    labels=None,
    **kwargs,
):
    return Infrastructure(
        id=pycti.Infrastructure.generate_id(name=name),
        created=created,
        name=name,
        first_seen=first_seen,
        labels=labels,
        infrastructure_types=infrastructure_types,
        **kwargs,
        **_additional_kwargs(created_by),
    )


def location(
    country: str,
    created: str,
    postal_code: str | None,
    created_by: str,
):
    name = _get_country_name(country)
    return Location(
        id=pycti.Location.generate_id(name=name, x_opencti_location_type="Country"),
        name=name,
        created=created,
        country=country,
        postal_code=postal_code,
        **_additional_kwargs(created_by),
    )


def malware(
    created_by: str,
    name: str = None,
    is_family: bool = True,
    **kwargs,
):
    return Malware(
        id=pycti.Malware.generate_id(name=name),
        name=name,
        is_family=is_family,
        **kwargs,
        **_additional_kwargs(created_by),
    )


def tool(
    created_by,
    description,
    created,
    urls: list,
    tool_types: list,
):
    return Tool(
        id=pycti.Tool.generate_id(name=description),
        created=created,
        description=description,
        external_references=[
            ExternalReference(source_name="link", url=url) for url in urls
        ],
        tool_types=tool_types,
        **_additional_kwargs(created_by),
    )


def vulnerability(
    created_by,
    cve,
    created,
    modified,
    description="",
):
    return Vulnerability(
        id=pycti.Vulnerability.generate_id(name=cve),
        name=cve,
        description=description,
        external_references=[ExternalReference(source_name="cve", external_id=cve)],
        created=created,
        modified=modified,
        **_additional_kwargs(created_by),
    )


def relationship(source: str, target: str, type: str, start_time: str = None):
    return Relationship(
        id=pycti.StixCoreRelationship.generate_id(type, source, target, start_time),
        source_ref=source,
        target_ref=target,
        relationship_type=type,
        start_time=start_time,
    )
