import ipaddress
import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

domain_regex = re.compile(
    r"^(?=.{1,253}$)(?!-)(xn--)?(?:[A-Za-z0-9À-ÿ-_]{1,63}(?<!-)\.)+(?!-)(xn--)?[A-Za-z0-9À-ÿ-_]{2,63}(?<!-)$"
)
hostname_regex = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$"
)
mac_addr_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", re.IGNORECASE)
asn_regex = re.compile(r"^AS[-\s]?(\d+)$", re.IGNORECASE)
md5_regex = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
sha1_regex = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
sha256_regex = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
sha512_regex = re.compile(r"^[a-f0-9]{128}$", re.IGNORECASE)
email_regex = re.compile(
    r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)"
    r"+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
    re.IGNORECASE,
)


def _check_domain_name(value: str) -> str:
    if domain_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid Domain name: '{value}'")


def _check_hostname(value: str) -> str:
    if hostname_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid Hostname: '{value}'")


def _check_mac_addr(value: str) -> str:
    if mac_addr_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid Mac Address: '{value}'")


def _check_md5(value: str) -> str:
    if md5_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid MD5 hash: '{value}'")


def _check_sha1(value: str) -> str:
    if sha1_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid SHA1 hash: '{value}'")


def _check_sha256(value: str) -> str:
    if sha256_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid SHA256 hash: '{value}'")


def _check_sha512(value: str) -> str:
    if sha512_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid SHA512 hash: '{value}'")


def _check_email_addr(value: str) -> str:
    if email_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid Email Address: '{value}'")


def _check_asn(value: str) -> str:
    if asn_regex.match(value):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Invalid Autonomous-System: '{value}'")


def _check_ip_address_or_network(value: str) -> str:
    # Deleting start/end spaces
    value = value.strip()
    # If spacing characters are identified, an error is returned
    if re.search(r"\s", value):
        raise ValueError(
            f"[VALIDATION-ERROR] IP address/network invalide (Spacer character identified): '{value}'"
        )

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise ValueError(f"[VALIDATION-ERROR] IP address/network invalide : '{value}'")


def _no_check(value: str) -> str:
    if isinstance(value, str):
        return value
    raise ValueError(f"[VALIDATION-WARNING] Expected a string. (value: '{value}')")


VALIDATION_BY_TYPE = {
    "Domain-Name": _check_domain_name,
    "Url": _no_check,
    "Hostname": _check_hostname,
    "Email-Addr": _check_email_addr,
    "Email-Message--Body": _no_check,
    "Email-Message--Message_id": _no_check,
    "Email-Message--Subject": _no_check,
    "IPv4-Addr": _check_ip_address_or_network,
    "IPv6-Addr": _check_ip_address_or_network,
    "Mac-Addr": _check_mac_addr,
    "MD5": _check_md5,
    "SHA-1": _check_sha1,
    "SHA-256": _check_sha256,
    "SHA-512": _check_sha512,
    "StixFile": _no_check,
    "Directory": _no_check,
    "Mutex": _no_check,
    "Autonomous-System": _check_asn,
    "Phone-Number": _no_check,
    "Windows-Registry-Key": _no_check,
    "User-Account": _no_check,
    # --- Not Observables ---
    "CVE-Number": _no_check,
    "Organization-Name": _no_check,
}

# TYPE_MAPPING -> "ServiceNow_Type_Name": "OpenCTI_Type_Name"
TYPE_MAPPING = {
    "Domain name": "Domain-Name",
    "Top-level domain name": "Domain-Name",
    "Host name": "Hostname",
    "URL": "Url",
    "URI": "Url",
    "Email address": "Email-Addr",
    "Email body": "Email-Message--Body",
    "Email Message ID": "Email-Message--Message_id",
    "Email subject": "Email-Message--Subject",
    "IP address (V4)": "IPv4-Addr",
    "IP address (V6)": "IPv6-Addr",
    "IPV4 Network": "IPv4-Addr",
    "IPV6 Network": "IPv6-Addr",
    "MAC address": "Mac-Addr",
    "MD5 hash": "MD5",
    "SHA1 hash": "SHA-1",
    "SHA256 hash": "SHA-256",
    "SHA512 hash": "SHA-512",
    "File": "StixFile",
    "File Name": "StixFile",
    "File path": "Directory",
    "MUTEX name": "Mutex",
    "Autonomous System Number": "Autonomous-System",
    "Phone number": "Phone-Number",
    "Registry key": "Windows-Registry-Key",
    "Username": "User-Account",
    "CVE number": "CVE-Number",
    "Organization name": "Organization-Name",
}


class ObservableResponse(BaseModel):
    sys_id: str = Field(description="")
    value: str = Field(description="")
    type: str = Field(description="")
    finding: Optional[list[str]] = Field(default=None)
    sys_tags: Optional[list[str]] = Field(default=None)
    security_tags: Optional[list[str]] = Field(default=None)
    sys_created_on: Optional[datetime] = Field(default=None)
    sys_updated_on: Optional[datetime] = Field(default=None)
    notes: Optional[str] = Field(default=None)

    @model_validator(mode="before")
    def strip_observable_prefix_and_validate_type(cls, data: dict) -> dict:
        new_data = {
            (
                key.replace("observable.", "") if key.startswith("observable.") else key
            ): value
            for key, value in data.items()
        }

        raw_type = new_data.get("type")
        raw_value = new_data.get("value")
        type_mapped = TYPE_MAPPING.get(raw_type)
        if not type_mapped:
            raise ValueError(
                f"[VALIDATION-WARNING] The type of the observable is missing or is not managed correctly, so the "
                f"observable will be ignored. (value: '{raw_value}', type: '{raw_type}')"
            )
        new_data["type"] = type_mapped
        return new_data

    @model_validator(mode="after")
    def validate_value_by_type(self):
        observable_type = self.type
        observable_value = self.value

        validator = VALIDATION_BY_TYPE.get(observable_type)
        if not validator:
            raise ValueError(
                f"[VALIDATION-WARNING] No validator found for type '{observable_type}'."
            )

        validated_value = validator(observable_value)
        self.value = validated_value
        return self

    @field_validator("finding", "sys_tags", "security_tags", mode="before")
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip() for x in value.split(",") if x.strip()]
        return value

    @field_validator("sys_created_on", "sys_updated_on", mode="before")
    def parse_datetime(cls, value):
        if isinstance(value, str) and not value.strip():
            return None
        return value


class TaskResponse(BaseModel):
    sys_id: str = Field(description="")
    number: str = Field(description="")
    short_description: str = Field(description="")
    description: Optional[str] = Field(default=None)
    sys_created_on: Optional[datetime] = Field(default=None)
    sys_updated_on: Optional[datetime] = Field(default=None)
    due_date: Optional[datetime] = Field(default=None)
    sys_tags: Optional[list[str]] = Field(default=None)
    security_tags: Optional[list[str]] = Field(default=None)
    comments_and_work_notes: Optional[str] = Field(default=None)
    get_observables: Optional[list[ObservableResponse]] = Field(default=None)

    @field_validator("sys_tags", "security_tags", mode="before")
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip() for x in value.split(",") if x.strip()]
        return value

    @field_validator("sys_created_on", "sys_updated_on", "due_date", mode="before")
    def parse_datetime(cls, value):
        if isinstance(value, str) and not value.strip():
            return None
        return value


class SecurityIncidentResponse(BaseModel):
    sys_id: str = Field(description="")
    number: str = Field(description="")
    short_description: str = Field(description="")
    description: Optional[str] = Field(default=None)
    state: Optional[str] = Field(default=None)
    priority: Optional[str] = Field(default=None)
    severity: Optional[str] = Field(default=None)
    category: Optional[str] = Field(default=None)
    subcategory: Optional[list[str]] = Field(default=None)
    comments_and_work_notes: Optional[str] = Field(default=None)
    sys_tags: Optional[list[str]] = Field(default=None)
    security_tags: Optional[list[str]] = Field(default=None)
    contact_type: Optional[list[str]] = Field(default=None)
    alert_sensor: Optional[list[str]] = Field(default=None)
    estimated_end: Optional[datetime] = Field(default=None)
    sys_created_on: Optional[datetime] = Field(default=None)
    sys_updated_on: Optional[datetime] = Field(default=None)
    mitre_technique: Optional[list[str]] = Field(default=None)
    mitre_tactic: Optional[list[str]] = Field(default=None)
    mitre_group: Optional[list[str]] = Field(default=None)
    mitre_malware: Optional[list[str]] = Field(default=None)
    mitre_tool: Optional[list[str]] = Field(default=None)
    get_tasks: Optional[list[TaskResponse]] = Field(default=None)
    get_observables: Optional[list[ObservableResponse]] = Field(default=None)

    @field_validator(
        "mitre_technique",
        "mitre_tactic",
        "mitre_group",
        "mitre_malware",
        "mitre_tool",
        "subcategory",
        "sys_tags",
        "security_tags",
        "contact_type",
        "alert_sensor",
        mode="before",
    )
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip() for x in value.split(",") if x.strip()]
        return value

    @field_validator("estimated_end", "sys_created_on", "sys_updated_on", mode="before")
    def parse_datetime(cls, value):
        if isinstance(value, str) and not value.strip():
            return None
        return value
