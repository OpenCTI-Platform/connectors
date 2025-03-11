"""Provide custom types for Pydantic models."""

from enum import Enum
from typing import Annotated, Any, Callable

from pydantic import AfterValidator

import dragos.domain.models.octi.enum as OCTIEnum


def is_in_enum(enum: Enum) -> Callable:
    """Get validator to check if a value is in given enum."""

    def compare_value(value: Any) -> Any:
        """Check if value is in enum."""
        enum_values = [member.value for member in enum]
        if value not in enum_values:
            raise ValueError(
                f"Invalid value '{value}'. Allowed values are: {', '.join(enum_values)}"
            )
        return value

    return compare_value


AccountType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.AccountType))]

AttackMotivation = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.AttackMotivation))]

AttackResourceLevel = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.AttackResourceLevel))
]

CvssSeverity = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.CvssSeverity))]

EncryptionAlgorithm = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.EncryptionAlgorithm))
]

HashAlgorithm = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.HashAlgorithm))]

ImplementationLanguage = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.ImplementationLanguage))
]

IndicatorType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.IndicatorType))]

LocationType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.LocationType))]

MalwareCapability = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.MalwareCapability))
]

MalwareType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.MalwareType))]

ObservableType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.ObservableType))]

OrganizationType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.OrganizationType))]

PatternType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.PatternType))]

Platform = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.Platform))]

ProcessorArchitecture = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.ProcessorArchitecture))
]

Region = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.Region))]

Reliability = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.Reliability))]

ReportType = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.ReportType))]

TLPLevel = Annotated[str, AfterValidator(is_in_enum(OCTIEnum.TLPLevel))]

WindowsRegistryDatatype = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsRegistryDatatype))
]

WindowsIntegrityLevel = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsIntegrityLevel))
]

WindowsServiceStartType = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsServiceStartType))
]

WindowsServiceStatus = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsServiceStatus))
]

WindowsServiceType = Annotated[
    str, AfterValidator(is_in_enum(OCTIEnum.WindowsServiceType))
]
